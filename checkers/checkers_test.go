package checkers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cc-permission-handler/check"
	"cc-permission-handler/config"
	configpb "cc-permission-handler/gen/config/v1"
	"cc-permission-handler/walker"

	"google.golang.org/protobuf/proto"
	"mvdan.cc/sh/v3/syntax"
)

func TestMain(m *testing.M) {
	config.SetGlobal(&configpb.Config{
		Projects: []*configpb.Project{
			{
				PathPatterns:       []string{"/**"},
				AllowWritePatterns: []string{"/tmp/**"},
			},
			{
				PathPatterns:      []string{"/project/**"},
				AllowProjectWrite: proto.Bool(true),
				RemoteHosts: []*configpb.RemoteHost{{
					HostPatterns:       []string{"test.example.com"},
					AllowWritePatterns: []string{"/tmp/**"},
				}},
			},
		},
	})
	os.Exit(m.Run())
}

func parseCall(t *testing.T, cmd string) []*syntax.Word {
	t.Helper()
	f, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
	if err != nil {
		t.Fatalf("parse %q: %v", cmd, err)
	}
	if len(f.Stmts) != 1 {
		t.Fatalf("expected 1 stmt, got %d", len(f.Stmts))
	}
	call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		t.Fatalf("expected CallExpr, got %T", f.Stmts[0].Cmd)
	}
	return call.Args
}

func testContext(cwd string) *check.Context {
	return &check.Context{
		Cwd:       cwd,
		WriteDirs: []string{"/tmp"},
		IsPathAllowed: func(path string) bool {
			if path == "/dev/null" {
				return true
			}
			if cwd == "" {
				return false
			}
			resolved := path
			if !filepath.IsAbs(path) {
				resolved = filepath.Join(cwd, path)
			}
			for _, dir := range []string{cwd, "/tmp"} {
				if check.IsPathUnder(resolved, dir) {
					return true
				}
			}
			return false
		},
		Evaluate: walker.EvaluateWithDirs,
	}
}

func TestGitChecker_ConfigReadOnly(t *testing.T) {
	ctx := testContext("/project")
	tests := []struct {
		name  string
		cmd   string
		allow bool
	}{
		{name: "key lookup", cmd: "git config user.name", allow: true},
		{name: "--get", cmd: "git config --get user.name", allow: true},
		{name: "--list", cmd: "git config --list", allow: true},
		{name: "-l", cmd: "git config -l", allow: true},
		{name: "--get-all", cmd: "git config --get-all user.name", allow: true},
		{name: "--get-regexp", cmd: "git config --get-regexp 'user.*'", allow: true},
		{name: "--file read", cmd: "git config --file .gitconfig user.name", allow: true},
		{name: "--global key", cmd: "git config --global user.name", allow: true},
		{name: "set value", cmd: `git config user.name "Kevin"`, allow: false},
		{name: "core.hooksPath", cmd: "git config core.hooksPath /tmp/evil", allow: false},
		{name: "alias", cmd: `git config alias.x '!rm -rf /'`, allow: false},
		{name: "--global set", cmd: `git config --global user.email "x@y"`, allow: false},
		{name: "--unset", cmd: "git config --unset user.name", allow: false},
	}
	c := gitChecker{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := parseCall(t, tt.cmd)
			if got := c.Check(ctx, args); got != tt.allow {
				t.Errorf("gitChecker.Check(%q) = %v, want %v", tt.cmd, got, tt.allow)
			}
		})
	}
}

func TestGoChecker_RunPaths(t *testing.T) {
	ctx := testContext("/project")
	tests := []struct {
		name  string
		cmd   string
		allow bool
	}{
		{name: "go run dot", cmd: "go run .", allow: true},
		{name: "go run relative", cmd: "go run ./cmd/server", allow: true},
		{name: "go run file", cmd: "go run main.go", allow: true},
		{name: "go run with flags", cmd: "go run -race ./cmd/server", allow: true},
		{name: "go run project abs", cmd: "go run /project/main.go", allow: true},
		{name: "go run /tmp", cmd: "go run /tmp/evil.go", allow: false},
		{name: "go run /etc", cmd: "go run /etc/backdoor.go", allow: false},
	}
	c := goChecker{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := parseCall(t, tt.cmd)
			if got := c.Check(ctx, args); got != tt.allow {
				t.Errorf("goChecker.Check(%q) = %v, want %v", tt.cmd, got, tt.allow)
			}
		})
	}
}

func TestPathWriteChecker(t *testing.T) {
	ctx := testContext("/project")
	tests := []struct {
		name  string
		cmd   string
		allow bool
	}{
		{name: "mkdir in /tmp", cmd: "mkdir -p /tmp/dir", allow: true},
		{name: "touch in project", cmd: "touch file.txt", allow: true},
		{name: "cp to /tmp", cmd: "cp file /tmp/backup", allow: true},
		{name: "cp outside", cmd: "cp file /etc/evil", allow: false},
		{name: "mkdir outside", cmd: "mkdir /etc/evil", allow: false},
		{name: "rm in /tmp", cmd: "rm /tmp/junk", allow: true},
		{name: "rm root", cmd: "rm -rf /", allow: false},
		// --target-directory in both forms
		{name: "cp --target-directory= /tmp", cmd: "cp --target-directory=/tmp file", allow: true},
		{name: "cp --target-directory /tmp", cmd: "cp --target-directory /tmp file", allow: true},
		{name: "cp -t /tmp", cmd: "cp -t /tmp file", allow: true},
		{name: "cp -t /etc", cmd: "cp -t /etc file", allow: false},
		{name: "mv -t /tmp", cmd: "mv -t /tmp file", allow: true},
		// Non-path flags with args should be skipped
		{name: "cp --backup numbered", cmd: "cp --backup numbered file /tmp/dest", allow: true},
		{name: "cp -S .bak", cmd: "cp -S .bak file /tmp/dest", allow: true},
		{name: "cp --suffix=.bak", cmd: "cp --suffix=.bak file /tmp/dest", allow: true},
		// -- separator
		{name: "rm -- /tmp/file", cmd: "rm -- /tmp/file", allow: true},
		{name: "rm -- /etc/file", cmd: "rm -- /etc/file", allow: false},
	}
	c := pathWriteChecker{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := parseCall(t, tt.cmd)
			if got := c.Check(ctx, args); got != tt.allow {
				t.Errorf("pathWriteChecker.Check(%q) = %v, want %v", tt.cmd, got, tt.allow)
			}
		})
	}
}

func TestFindChecker(t *testing.T) {
	ctx := testContext("/project")
	tests := []struct {
		name  string
		cmd   string
		allow bool
	}{
		{name: "name and print", cmd: "find . -name '*.go' -print", allow: true},
		{name: "type and maxdepth", cmd: "find . -type f -maxdepth 3", allow: true},
		{name: "multiple primaries", cmd: "find /project -name '*.go' -not -path '*/vendor/*' -print0", allow: true},
		{name: "printf format", cmd: "find . -name '*.go' -printf '%p\\n'", allow: true},
		{name: "prune and or", cmd: "find . -name .git -prune -or -name '*.go' -print", allow: true},
		{name: "exec denied", cmd: `find . -exec rm {} \;`, allow: false},
		{name: "execdir denied", cmd: `find . -execdir cat {} \;`, allow: false},
		{name: "delete denied", cmd: "find . -name '*.tmp' -delete", allow: false},
		{name: "fprint denied", cmd: "find . -fprint /etc/evil", allow: false},
		{name: "fprint0 denied", cmd: "find . -fprint0 /etc/evil", allow: false},
		{name: "ok denied", cmd: `find . -ok rm {} \;`, allow: false},
	}
	c := findChecker{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := parseCall(t, tt.cmd)
			if got := c.Check(ctx, args); got != tt.allow {
				t.Errorf("findChecker.Check(%q) = %v, want %v", tt.cmd, got, tt.allow)
			}
		})
	}
}

func TestFdChecker(t *testing.T) {
	ctx := testContext("/project")
	tests := []struct {
		name  string
		cmd   string
		allow bool
	}{
		{name: "simple pattern", cmd: "fd pattern", allow: true},
		{name: "with type", cmd: "fd -t f pattern", allow: true},
		{name: "extension and hidden", cmd: "fd -e go -H", allow: true},
		{name: "max-depth with =", cmd: "fd --max-depth=3 pattern", allow: true},
		{name: "exec denied", cmd: "fd -x rm", allow: false},
		{name: "exec-batch denied", cmd: "fd --exec-batch cat", allow: false},
		{name: "long exec denied", cmd: "fd --exec rm", allow: false},
		{name: "unknown flag denied", cmd: "fd --unknown pattern", allow: false},
	}
	c := fdChecker{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := parseCall(t, tt.cmd)
			if got := c.Check(ctx, args); got != tt.allow {
				t.Errorf("fdChecker.Check(%q) = %v, want %v", tt.cmd, got, tt.allow)
			}
		})
	}
}

func TestSedChecker(t *testing.T) {
	ctx := testContext("/project")
	tests := []struct {
		name  string
		cmd   string
		allow bool
	}{
		{name: "simple subst", cmd: "sed 's/foo/bar/g'", allow: true},
		{name: "delete pattern", cmd: "sed '/pattern/d'", allow: true},
		{name: "multiple -e", cmd: "sed -e 's/a/b/' -e '/x/d'", allow: true},
		{name: "translate", cmd: "sed 'y/abc/xyz/'", allow: true},
		{name: "print", cmd: "sed -n '/foo/p'", allow: true},
		{name: "address range", cmd: "sed '1,10d'", allow: true},
		{name: "dollar address", cmd: "sed '$d'", allow: true},
		{name: "hold space", cmd: "sed -n 'h;n;H;g;p'", allow: true},
		{name: "branch", cmd: "sed ':a;N;$!ba;s/\\n/ /g'", allow: true},
		{name: "append text", cmd: `sed '/foo/a\new line'`, allow: true},
		{name: "read file", cmd: "sed '/foo/r input.txt'", allow: true},
		// Dangerous commands
		{name: "e flag on subst", cmd: "sed 's/foo/bar/e'", allow: false},
		{name: "w command", cmd: "sed 'w /etc/evil'", allow: false},
		{name: "W command", cmd: "sed 'W /etc/evil'", allow: false},
		{name: "e command", cmd: "sed 'e'", allow: false},
		{name: "w flag on subst", cmd: "sed 's/foo/bar/w /tmp/out'", allow: false},
		{name: "-i flag", cmd: "sed -i 's/foo/bar/' file", allow: false},
		{name: "--in-place", cmd: "sed --in-place 's/foo/bar/' file", allow: false},
		{name: "-f script", cmd: "sed -f script.sed file", allow: false},
	}
	c := sedChecker{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := parseCall(t, tt.cmd)
			if got := c.Check(ctx, args); got != tt.allow {
				t.Errorf("sedChecker.Check(%q) = %v, want %v", tt.cmd, got, tt.allow)
			}
		})
	}
}

func TestAwkChecker(t *testing.T) {
	ctx := testContext("/project")
	tests := []struct {
		name  string
		cmd   string
		allow bool
	}{
		{name: "simple print", cmd: "awk '{print $1}'", allow: true},
		{name: "field separator", cmd: "awk -F: '{print $1}'", allow: true},
		{name: "comparison >=", cmd: "awk '{if (a >= b) print}'", allow: true},
		{name: "comparison >", cmd: "awk '$3 > 100' file.txt", allow: true},
		{name: "NR comparison", cmd: "awk 'NR > 5 && NR < 10' file.txt", allow: true},
		{name: "regex alternation", cmd: "awk '/foo|bar/ {print}' file.txt", allow: true},
		{name: "logical or ||", cmd: "awk '{if (a || b) print}'", allow: true},
		{name: "with -v", cmd: "awk -v x=1 '{print x}'", allow: true},
		{name: "with -e", cmd: "awk -e '{print $1}'", allow: true},
		// Dangerous patterns
		{name: "redirect to var", cmd: "awk -v f=/etc/passwd '{print > f}'", allow: false},
		{name: "redirect to literal", cmd: `awk '{print > "/tmp/out"}'`, allow: false},
		{name: "redirect no space", cmd: `awk '{print >"/tmp/out"}'`, allow: false},
		{name: "redirect abs path", cmd: `awk '{print > /tmp/file}' input`, allow: false},
		{name: "append >>", cmd: `awk '{print >> "file"}'`, allow: false},
		{name: "pipe out", cmd: `awk '{print | "cmd"}'`, allow: false},
		{name: "system call", cmd: `awk '{system("ls")}'`, allow: false},
		{name: "getline", cmd: "awk '{getline line}'", allow: false},
		{name: "-f script", cmd: "awk -f script.awk", allow: false},
	}
	c := awkChecker{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := parseCall(t, tt.cmd)
			if got := c.Check(ctx, args); got != tt.allow {
				t.Errorf("awkChecker.Check(%q) = %v, want %v", tt.cmd, got, tt.allow)
			}
		})
	}
}

func TestParseSSHArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantHost string
		wantCmd  string
		wantOK   bool
	}{
		{name: "simple", args: []string{"host", "git", "status"}, wantHost: "host", wantCmd: "git status", wantOK: true},
		{name: "with dashdash", args: []string{"host", "--", "git", "status"}, wantHost: "host", wantCmd: "git status", wantOK: true},
		{name: "with -p flag", args: []string{"-p", "22", "host", "git", "status"}, wantHost: "host", wantCmd: "git status", wantOK: true},
		{name: "no remote command", args: []string{"host"}, wantHost: "host", wantCmd: "", wantOK: true},
		{name: "dangerous -o flag", args: []string{"-o", "ProxyCommand=evil", "host", "git", "status"}, wantHost: "", wantCmd: "", wantOK: false},
		{name: "dangerous -F flag", args: []string{"-F", "/evil/config", "host", "git", "status"}, wantHost: "", wantCmd: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, cmd, ok := parseSSHArgs(tt.args)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if cmd != tt.wantCmd {
				t.Errorf("cmd = %q, want %q", cmd, tt.wantCmd)
			}
		})
	}
}

func TestTshChecker(t *testing.T) {
	ctx := testContext("/project")
	tests := []struct {
		name  string
		cmd   string
		allow bool
	}{
		{name: "tsh ssh allowed host", cmd: "tsh ssh test.example.com git status", allow: true},
		{name: "tsh ssh with flags", cmd: "tsh ssh -p 22 test.example.com git log", allow: true},
		{name: "tsh ssh unknown host", cmd: "tsh ssh evil.host git status", allow: false},
		{name: "tsh ssh no remote cmd", cmd: "tsh ssh test.example.com", allow: false},
		{name: "tsh ssh unsafe inner", cmd: `tsh ssh test.example.com "rm -rf /"`, allow: false},
		{name: "tsh non-ssh subcommand", cmd: "tsh proxy app", allow: false},
		{name: "bare tsh", cmd: "tsh", allow: false},
	}
	c := tshChecker{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := parseCall(t, tt.cmd)
			if got := c.Check(ctx, args); got != tt.allow {
				t.Errorf("tshChecker.Check(%q) = %v, want %v", tt.cmd, got, tt.allow)
			}
		})
	}
}
