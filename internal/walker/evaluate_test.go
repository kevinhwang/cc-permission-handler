package walker

import (
	"os"
	"testing"

	_ "cc-permission-handler/internal/checkers"
	"cc-permission-handler/internal/config"
	configpb "cc-permission-handler/internal/gen/config/v1"
	rulespb "cc-permission-handler/internal/gen/rules/v1"
	"cc-permission-handler/internal/rules"

	"google.golang.org/protobuf/proto"
)

const testCwd = "/project"

var testRuleSet *rulespb.RuleSet

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
	var err error
	testRuleSet, err = rules.DefaultRules()
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func TestEvaluate_Allow(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
	}{
		{name: "simple git status", cmd: "git status"},
		{name: "ls with flags", cmd: "ls -la"},
		{name: "echo string", cmd: `echo "hello world"`},
		{name: "cat file", cmd: "cat file.txt"},
		{name: "grep pattern", cmd: "grep -r pattern src/"},
		{name: "cd and git", cmd: "cd dir && git status"},
		{name: "cd and agent-bzl", cmd: "cd .claude/worktrees/wt && agent-bzl test //pkg:test --test_output=streamed"},
		{name: "triple &&", cmd: "ls -la && pwd && echo hello"},
		{name: "git add and commit", cmd: "git add . && git commit -m 'fix bug'"},
		{name: "or fallback", cmd: "git pull || echo failed"},
		{name: "pipe git to head", cmd: "git log | head -20"},
		{name: "triple pipe", cmd: "cat file.txt | grep pattern | wc -l"},
		{name: "git log with redirect and pipe", cmd: "git log 2>&1 | head"},
		{name: "semicolon", cmd: "echo hello; echo world"},
		{name: "cd then pipe", cmd: "cd dir && git log | head -20"},
		{name: "complex chain", cmd: "cd dir && npm install && npm test"},
		{name: "subshell", cmd: "(cd dir && git status)"},
		{name: "nested subshell", cmd: "(cd dir && (echo a; echo b))"},
		{name: "block", cmd: "{ echo a; echo b; }"},
		{name: "if then fi", cmd: "if git diff --quiet; then echo clean; fi"},
		{name: "if then else fi", cmd: "if git diff --quiet; then echo clean; else echo dirty; fi"},
		{name: "if elif else", cmd: "if [ -f a ]; then cat a; elif [ -f b ]; then cat b; else echo none; fi"},
		{name: "for in do done", cmd: "for f in *.txt; do cat \"$f\"; done"},
		{name: "for with echo", cmd: "for i in 1 2 3; do echo $i; done"},
		{name: "while do done", cmd: "while ! grep -q ready status.txt; do sleep 1; done"},
		{name: "case", cmd: `case "$1" in *.txt) cat "$1";; *.md) head "$1";; esac`},
		{name: "case with subst word", cmd: `case "$(echo txt)" in *.txt) echo match;; esac`},
		{name: "test bracket", cmd: "[[ -f file.txt ]] && cat file.txt"},
		{name: "test with var", cmd: `[[ "$FOO" == "bar" ]] && echo yes`},
		{name: "cmd subst in arg", cmd: `echo "branch: $(git rev-parse --abbrev-ref HEAD)"`},
		{name: "cmd subst in arg 2", cmd: `echo "hash: $(git log -1 --format='%H')"`},
		{name: "nested safe subst", cmd: `echo "$(echo hello)"`},
		{name: "process subst", cmd: "diff <(git show HEAD:file) <(cat file)"},
		{name: "negation", cmd: "! git diff --quiet"},
		{name: "redirect to /dev/null", cmd: "git log > /dev/null"},
		{name: "stderr to /dev/null", cmd: "git log 2>/dev/null"},
		{name: "fd redirect", cmd: "git log 2>&1"},
		{name: "redirect to project dir", cmd: "git log > output.txt"},
		{name: "redirect to /tmp", cmd: "echo data > /tmp/file.txt"},
		{name: "redirect to /dev/null compound", cmd: "git log > /dev/null && echo done"},
		{name: "n> redirect safe", cmd: "echo foo 1>/dev/null"},
		{name: "env var prefix", cmd: "FOO=bar git status"},
		{name: "pure assignment", cmd: "FOO=bar"},
		{name: "export", cmd: "export FOO=bar"},
		{name: "export compound", cmd: "export FOO=bar && agent-bzl test //pkg:test"},
		// git -C now treated as unknown flag (skipped by default); subcommand still found
		{name: "git -C", cmd: "git -C /path status"},
		{name: "git -C with --no-pager", cmd: "git -C /path --no-pager log"},
		{name: "git --no-pager log", cmd: "git --no-pager log --oneline"},
		{name: "git config key lookup", cmd: "git config user.name"},
		{name: "git config --get", cmd: "git config --get user.name"},
		{name: "git config --list", cmd: "git config --list"},
		{name: "git config -l", cmd: "git config -l"},
		{name: "git config --get-all", cmd: "git config --get-all user.name"},
		{name: "git config --get-regexp", cmd: "git config --get-regexp 'user.*'"},
		{name: "git config --get-urlmatch", cmd: "git config --get-urlmatch http https://example.com"},
		{name: "git config --file read", cmd: "git config --file .gitconfig user.name"},
		{name: "git config --global key", cmd: "git config --global user.name"},
		{name: "ssh simple", cmd: "ssh test.example.com -- git status"},
		{name: "ssh no dashdash", cmd: "ssh test.example.com git status"},
		{name: "ssh with -p", cmd: "ssh -p 22 test.example.com -- git status"},
		{name: "ssh with -i", cmd: "ssh -i ~/.ssh/key test.example.com git log"},
		{name: "ssh with -tt", cmd: "ssh -tt test.example.com git status"},
		{name: "ssh quoted compound", cmd: `ssh test.example.com -- "cd /path && git status"`},
		{name: "tsh ssh simple", cmd: "tsh ssh test.example.com git status"},
		{name: "tsh ssh with flags", cmd: "tsh ssh -p 22 test.example.com -- git log"},
		{name: "npm install", cmd: "npm install"},
		{name: "npm test", cmd: "cd dir && npm test"},
		{name: "npm run build", cmd: "npm run build"},
		{name: "cargo build", cmd: "cd dir && cargo build"},
		{name: "go test", cmd: "cd dir && go test ./..."},
		{name: "pip install", cmd: "pip install -r requirements.txt"},
		{name: "bun install and test", cmd: "cd dir && bun install && bun test"},
		{name: "gh dbx pr", cmd: "gh dbx pr --apply-patches"},
		{name: "yarn install and build", cmd: "cd dir && yarn install && yarn build"},
		{name: "go run dot", cmd: "go run ."},
		{name: "go run relative", cmd: "go run ./cmd/server"},
		{name: "go run file", cmd: "go run main.go"},
		{name: "go run with flags", cmd: "go run -race ./cmd/server"},
		{name: "go run with -- args", cmd: "go run ./cmd/server -- --port=8080"},
		{name: "mkdir tmp", cmd: "mkdir -p /tmp/workdir"},
		{name: "touch tmp", cmd: "touch /tmp/marker.txt"},
		{name: "cp to tmp", cmd: "cp config.json /tmp/backup.json"},
		{name: "tee to tmp", cmd: "echo data | tee /tmp/log.txt"},
		{name: "cp target-dir tmp", cmd: "cp --target-directory=/tmp file.txt"},
		{name: "declare var", cmd: "declare -i num=5"},
		{name: "local var", cmd: "local foo=bar"},
		{name: "readonly var", cmd: "readonly PI=3.14"},
		{name: "arithm cmd", cmd: "(( x = 1 + 2 ))"},
		{name: "c-style for", cmd: "for ((i=0; i<10; i++)); do echo $i; done"},
		{name: "time cmd", cmd: "time git status"},
		{name: "let expr", cmd: "let x=1+2"},
		{name: "here-string", cmd: "cat <<< 'hello world'"},
		{name: "command -v", cmd: "command -v git"},
		{name: "command -V", cmd: "command -V git"},
		// command: only -v/-V allowed (simplified behavior)
		// command without -v and env with args moved to FallThrough tests
		{name: "bare env", cmd: "env"},
		{name: "awk print", cmd: `awk '{print $1}' file.txt`},
		{name: "awk with -F", cmd: `awk -F: '{print $1}' file.txt`},
		{name: "awk with -v", cmd: `awk -v OFS='\t' '{print $1, $2}' file.txt`},
		{name: "awk pipe", cmd: `cat file | awk '{print NR, $0}'`},
		{name: "gawk", cmd: `gawk '/pattern/ {print}' file.txt`},
		{name: "awk comparison", cmd: `awk '$3 > 100' file.txt`},
		{name: "awk NR comparison", cmd: `awk 'NR > 5 && NR < 10' file.txt`},
		{name: "awk regex with pipe", cmd: `awk '/foo|bar/ {print}' file.txt`},
		{name: "sort basic", cmd: "sort file.txt"},
		{name: "sort with flags", cmd: "sort -n -r file.txt"},
		{name: "sort unique", cmd: "sort -u file.txt"},
		{name: "find by name", cmd: `find . -name "*.go"`},
		{name: "find with type", cmd: `find /project -type f -name "*.txt"`},
		{name: "find with maxdepth", cmd: `find . -maxdepth 2 -name "*.md"`},
		{name: "find print0", cmd: `find . -name "*.log" -print0`},
		{name: "fd simple", cmd: `fd "*.go"`},
		{name: "fd with type", cmd: `fd -t f "*.txt" src/`},
		{name: "mktemp", cmd: "mktemp"},
		{name: "sleep compound", cmd: "sleep 2 && echo done"},
		{name: "set -e compound", cmd: "set -e && cd dir && npm test"},
		{name: "pushd popd", cmd: "pushd /some/dir && git status && popd"},
		{name: "ps pipe grep", cmd: "ps aux | grep node"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !Evaluate(tt.cmd, testCwd, testRuleSet) {
				t.Errorf("expected ALLOW for %q", tt.cmd)
			}
		})
	}
}

func TestEvaluate_FallThrough(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
	}{
		{name: "unknown command", cmd: "unknown_cmd arg1 arg2"},
		{name: "bash", cmd: "bash -c 'echo pwned'"},
		{name: "sh", cmd: "sh -c 'echo pwned'"},
		{name: "python", cmd: "python3 script.py"},
		{name: "node", cmd: "node script.js"},
		{name: "cmd subst as command", cmd: `$(echo rm) -rf /`},
		{name: "backtick as command", cmd: "`echo rm` -rf /"},
		{name: "param in command pos", cmd: "$CMD arg"},
		{name: "git -c hooksPath", cmd: "git -c core.hooksPath=/evil commit"},
		{name: "git -c pager", cmd: `git -c core.pager="rm -rf /" log`},
		{name: "git --config-env=", cmd: "git --config-env=CORE_EDITOR=EDITOR commit"},
		// git config is now allowed_with_any_args (simplified), so config
		// writes are no longer blocked. Moved to Allow tests or removed.
		// go run /tmp is now allowed (WriteCheck, /tmp in allowed write patterns)
		{name: "go run /etc", cmd: "go run /etc/backdoor.go"},
		{name: "ssh -o ProxyCommand", cmd: `ssh -o "ProxyCommand=evil" test.example.com git status`},
		{name: "ssh -F evil config", cmd: "ssh -F /evil/config test.example.com git status"},
		{name: "ssh -J jump host", cmd: "ssh -J jump.host test.example.com git status"},
		{name: "ssh unknown host", cmd: "ssh evil.host -- git status"},
		{name: "ssh no remote cmd", cmd: "ssh test.example.com"},
		{name: "ssh unsafe inner cmd", cmd: `ssh test.example.com -- "rm -rf /"`},
		{name: "tsh ssh unknown host", cmd: "tsh ssh evil.host git status"},
		{name: "tsh ssh unsafe inner", cmd: `tsh ssh test.example.com "rm -rf /"`},
		{name: "tsh non-ssh subcommand", cmd: "tsh proxy app"},
		{name: "npm exec", cmd: "npm exec -- dangerous-pkg"},
		{name: "pnpm dlx", cmd: "pnpm dlx dangerous-pkg"},
		{name: "yarn dlx", cmd: "yarn dlx dangerous-pkg"},
		{name: "bun x", cmd: "bun x dangerous-pkg"},
		{name: "npx", cmd: "npx some-package"},
		{name: "xargs", cmd: "echo danger | xargs bash"},
		{name: "make", cmd: "make build"},
		{name: "cmake", cmd: "cmake --build ."},
		{name: "docker", cmd: "docker run evil"},
		{name: "kubectl", cmd: "kubectl apply -f evil.yaml"},
		{name: "terraform", cmd: "terraform apply"},
		{name: "command rm", cmd: "command rm -rf /"},
		{name: "command bash", cmd: `command bash -c "echo pwned"`},
		{name: "command python", cmd: "command python3 script.py"},
		{name: "command -- unsafe", cmd: "command -- rm -rf /"},
		// env: simplified to bare-only
		{name: "env with flag", cmd: "env -0"},
		{name: "env with vars", cmd: "env FOO=bar BAZ=qux"},
		{name: "env wrapping safe cmd", cmd: "env FOO=bar git status"},
		{name: "env -i safe cmd", cmd: "env -i FOO=bar git log"},
		{name: "env -u safe cmd", cmd: "env -u HOME git status"},
		{name: "env wrapping bash", cmd: `env bash -c "echo pwned"`},
		{name: "env wrapping python", cmd: "env python3 script.py"},
		{name: "env -S", cmd: `env -S "bash -c echo"`},
		{name: "env --split-string", cmd: `env --split-string="bash -c echo"`},
		// command: simplified to -v/-V only
		{name: "command safe cmd", cmd: "command git status"},
		{name: "command -p safe cmd", cmd: "command -p git log"},
		{name: "command -- safe cmd", cmd: "command -- git status"},
		{name: "bare command", cmd: "command"},
		{name: "awk system", cmd: `awk '{system("echo pwned")}'`},
		{name: "awk getline", cmd: `awk '{cmd | getline result}' file`},
		{name: "awk -f external", cmd: "awk -f script.awk file"},
		{name: "gawk system", cmd: `gawk 'BEGIN{system("echo")}'`},
		{name: "awk file redirect", cmd: `awk '{print > "/tmp/out"}' file`},
		{name: "awk file append", cmd: `awk '{print >> "/tmp/out"}' file`},
		{name: "awk pipe to cmd", cmd: `awk '{print | "sort"}' file`},
		{name: "awk redirect no space", cmd: `awk '{print >"/tmp/out"}' file`},
		{name: "awk redirect abs path", cmd: `awk '{print > /tmp/file}' input`},
		{name: "find -exec", cmd: `find . -exec echo {} \;`},
		{name: "find -execdir", cmd: `find . -execdir echo {} \;`},
		{name: "find -delete", cmd: "find . -name '*.tmp' -delete"},
		{name: "find -ok", cmd: `find . -ok echo {} \;`},
		{name: "fd --exec", cmd: `fd "*.go" --exec echo {}`},
		{name: "fd -x", cmd: `fd "*.go" -x echo {}`},
		{name: "fd --exec-batch", cmd: `fd "*.go" --exec-batch echo`},
		{name: "fd -X", cmd: `fd "*.go" -X echo`},
		{name: "sed -i", cmd: "sed -i 's/foo/bar/' file.txt"},
		{name: "sed -ni", cmd: "sed -ni 's/foo/bar/p' file.txt"},
		{name: "sed --in-place", cmd: "sed --in-place 's/foo/bar/' file.txt"},
		{name: "yq -i", cmd: "yq -i '.foo = 1' file.yaml"},
		// sort -o is now WRITE_CHECK (allowed if path in allowed dir).
		// With testCwd=/project and allow_project_write, output.txt resolves
		// to /project/output.txt which is allowed. Moved to Allow tests.
		{name: "sort -o outside", cmd: "sort -o /etc/output.txt input.txt"},
		{name: "sed e standalone", cmd: "sed 'e' file"},
		{name: "sed s///e flag", cmd: "sed 's/foo/bar/e' file"},
		{name: "sed s///ge flags", cmd: "sed 's/foo/bar/ge' file"},
		{name: "sed -e with e cmd", cmd: "sed -e 'e' file"},
		{name: "sed -f external", cmd: "sed -f script.sed file"},
		{name: "sed w standalone", cmd: "sed 'w /etc/passwd' file"},
		{name: "sed W standalone", cmd: "sed 'W /etc/passwd' file"},
		{name: "sed s///w flag", cmd: "sed 's/foo/bar/w /etc/passwd' file"},
		{name: "sed s///gw flags", cmd: "sed 's/foo/bar/gw /etc/passwd' file"},
		{name: "sed semicolon w", cmd: "sed 'd;w /etc/passwd' file"},
		{name: "redirect to /etc", cmd: "echo foo > /etc/passwd"},
		{name: "n> redirect outside", cmd: "echo foo 1>/etc/passwd"},
		{name: "redirect with traversal", cmd: "echo foo > ../../etc/passwd"},
		{name: "background", cmd: "echo hello &"},
		{name: "background compound", cmd: "sleep 1 &"},
		{name: "func def", cmd: "foo() { rm -rf /; }"},
		{name: "coproc", cmd: "coproc cat"},
		{name: "trap", cmd: "trap 'echo pwned' EXIT"},
		{name: "eval", cmd: `eval "rm -rf /"`},
		{name: "exec", cmd: "exec rm -rf /"},
		{name: "source", cmd: "source evil_script.sh"},
		{name: "dot source", cmd: ". evil_script.sh"},
		{name: "if unsafe body", cmd: "if true; then rm -rf /; fi"},
		{name: "for unsafe body", cmd: "for f in *; do rm \"$f\"; done"},
		{name: "c-style for unsafe body", cmd: "for ((i=0; i<3; i++)); do rm -rf /; done"},
		{name: "c-style for unsafe expr", cmd: "for ((i=$(rm -rf /); i<3; i++)); do echo $i; done"},
		{name: "while unsafe body", cmd: "while true; do rm -rf /; done"},
		{name: "subshell unsafe", cmd: "(rm -rf /)"},
		{name: "block unsafe", cmd: "{ rm -rf /; }"},
		{name: "case unsafe body", cmd: "case x in *) rm -rf /;; esac"},
		{name: "case unsafe pattern subst", cmd: `case x in $(rm -rf /)) echo match;; esac`},
		{name: "if unsafe cond", cmd: "if rm -rf /; then echo done; fi"},
		{name: "while unsafe cond", cmd: "while rm -rf /; do echo done; done"},
		{name: "arithm unsafe subst", cmd: `(( x = $(rm -rf /) ))`},
		{name: "let unsafe subst", cmd: `let "x=$(rm -rf /)+1"`},
		{name: "time unsafe inner", cmd: "time rm -rf /"},
		{name: "unsafe subst in arg", cmd: `echo "$(rm -rf /)"  `},
		{name: "unsafe proc subst", cmd: "cat <(rm -rf /)"},
		{name: "unsafe param default", cmd: `echo "${HOME:-$(rm -rf /)}" `},
		{name: "pipe to bash", cmd: "echo 'rm -rf /' | bash"},
		{name: "pipe to python", cmd: "echo 'import os' | python3"},
		{name: "multi-line unsafe", cmd: "echo safe\nrm -rf /"},
		{name: "cp target-dir outside", cmd: "cp --target-directory=/etc file.txt"},
		{name: "mv target-dir outside", cmd: "mv --target-directory=/etc file.txt"},
		{name: "cp outside", cmd: "cp file.txt /etc/evil"},
		{name: "mkdir outside", cmd: "mkdir /etc/evil"},
		{name: "rm outside", cmd: "rm -rf /"},
		{name: "touch outside", cmd: "touch /etc/passwd"},
		{name: "export unsafe subst", cmd: "export FOO=$(rm -rf /)"},
		{name: "declare unsafe", cmd: "declare FOO=$(rm -rf /)"},
		{name: "safe then unsafe", cmd: "echo hello && rm -rf /"},
		{name: "unsafe then safe", cmd: "rm -rf / && echo hello"},
		{name: "safe pipe unsafe", cmd: "echo data | bash"},
		// --- Tilde expansion bypass (bash expands ~ to $HOME) ---
		{name: "redirect to ~/", cmd: "echo evil >> ~/.bashrc"},
		{name: "touch ~/", cmd: "touch ~/.ssh/authorized_keys"},
		{name: "cp to ~/", cmd: "cp file ~/.profile"},
		{name: "redirect ~/traversal", cmd: "echo evil > ~/../../etc/passwd"},

		// --- PATH hijack via prefix assignment ---
		{name: "PATH=. hijack", cmd: "PATH=.:$PATH git status"},
		{name: "PATH=/tmp hijack", cmd: "PATH=/tmp:$PATH git log"},
		{name: "PATH override", cmd: "PATH=/evil git status"},

		{name: "redirect with var", cmd: "echo foo > $FILE"},
		{name: "redirect with subst", cmd: "echo foo > $(echo /tmp/file)"},
		{name: "env subst as cmd", cmd: `env $(printf git) status`},
		{name: "env subst safe inner dangerous output", cmd: `env $(printf python3) script.py`},
		{name: "env param as cmd", cmd: `env $CMD arg`},
		{name: "git subst subcommand", cmd: `git $(echo status)`},
		{name: "git param subcommand", cmd: `git $SUBCMD`},
		{name: "npm subst subcommand", cmd: `npm $(echo install)`},
		{name: "cargo subst subcommand", cmd: `cargo $(echo build)`},
		{name: "ssh subst remote cmd", cmd: `ssh test.example.com $(echo 'git status')`},
		{name: "ssh param remote cmd", cmd: `ssh test.example.com $CMD`},
		{name: "awk subst program", cmd: `awk "$(printf '{print}')" file`},
		{name: "awk param program", cmd: `awk "$PROG" file`},
		{name: "sed subst program", cmd: `sed "$(printf 's/a/b/')" file`},
		{name: "sed param program", cmd: `sed "$PROG" file`},
		{name: "find subst flag", cmd: `find . $(echo -exec) echo {} \;`},
		{name: "find param flag", cmd: `find . $FLAG echo {} \;`},
		{name: "fd subst flag", cmd: `fd pattern $(echo --exec) echo`},
		{name: "cp subst path", cmd: `cp file $(echo /tmp/backup)`},
		{name: "mkdir subst path", cmd: `mkdir $(echo /tmp/dir)`},
		{name: "cp param path", cmd: `cp file $DEST`},
		{name: "for body param as cmd", cmd: `for cmd in safe1 safe2; do $cmd; done`},
		{name: "for subst items unsafe body", cmd: `for cmd in $(echo "a b"); do $cmd; done`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if Evaluate(tt.cmd, testCwd, testRuleSet) {
				t.Errorf("expected FALL-THROUGH for %q", tt.cmd)
			}
		})
	}
}

func TestEvaluate_NoCwd(t *testing.T) {
	t.Run("redirect to dev null", func(t *testing.T) {
		if !Evaluate("git log > /dev/null", "", testRuleSet) {
			t.Error("expected allow")
		}
	})
	t.Run("redirect to file falls through", func(t *testing.T) {
		if Evaluate("git log > output.txt", "", testRuleSet) {
			t.Error("expected fall-through")
		}
	})
}

func TestEvaluate_SymtabResolution(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		tests := []struct {
			name string
			cmd  string
		}{
			{
				name: "var in redirect path",
				cmd:  `DIR="/tmp/out" && echo data > "$DIR/file.txt"`,
			},
			{
				name: "var in rm path allowed dir",
				cmd:  `TARGET="/tmp/cleanup" && rm -rf "$TARGET"`,
			},
			{
				name: "chained var assignment",
				cmd:  `A="/tmp" && B="$A/build" && mkdir -p "$B"`,
			},
			{
				name: "export then use",
				cmd:  `export DIR="/tmp/out" && touch "$DIR/marker"`,
			},
			{
				name: "declare then use",
				cmd:  `declare DIR="/tmp/out" && touch "$DIR/marker"`,
			},
			{
				name: "local then use",
				cmd:  `local DIR="/tmp/out" && touch "$DIR/marker"`,
			},
			{
				name: "readonly then use",
				cmd:  `readonly DIR="/tmp/out" && touch "$DIR/marker"`,
			},
			{
				name: "var in cp destination",
				cmd:  `DEST="/tmp/backup" && cp file.txt "$DEST/file.txt"`,
			},
			{
				name: "var with literal prefix",
				cmd:  `NAME="output" && echo data > "/tmp/${NAME}.txt"`,
			},
			{
				name: "reassignment overwrites",
				cmd:  `DIR="/etc" && DIR="/tmp/safe" && rm -rf "$DIR"`,
			},
			{
				name: "empty assignment is empty string",
				cmd:  `SUFFIX= && echo data > "/tmp/file${SUFFIX}.txt"`,
			},
			{
				name: "brace group propagates vars",
				cmd:  `{ DIR="/tmp/out"; } && touch "$DIR/marker"`,
			},
			{
				name: "var in sort -o flag arg",
				cmd:  `OUT="/tmp/sorted.txt" && sort -o "$OUT" input.txt`,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if !Evaluate(tt.cmd, testCwd, testRuleSet) {
					t.Errorf("expected ALLOW for %q", tt.cmd)
				}
			})
		}
	})

	t.Run("fall_through", func(t *testing.T) {
		tests := []struct {
			name string
			cmd  string
		}{
			{
				name: "var resolves to dangerous path",
				cmd:  `TARGET="/etc" && rm -rf "$TARGET"`,
			},
			{
				name: "chained var resolves outside allowed",
				cmd:  `A="/etc" && B="$A/crontab" && touch "$B"`,
			},
			{
				name: "var invalidated by if",
				cmd:  "DIR=/tmp/safe\nif true; then DIR=/etc; fi\nrm -rf \"$DIR\"",
			},
			{
				name: "var invalidated by for loop",
				cmd:  "DIR=/tmp/safe\nfor i in 1; do DIR=/etc; done\nrm -rf \"$DIR\"",
			},
			{
				name: "var invalidated by while loop",
				cmd:  "DIR=/tmp/safe\nwhile false; do DIR=/etc; done\nrm -rf \"$DIR\"",
			},
			{
				name: "var invalidated by case",
				cmd:  "DIR=/tmp/safe\ncase x in *) DIR=/etc;; esac\nrm -rf \"$DIR\"",
			},
			{
				name: "var from command subst unresolvable",
				cmd:  `DIR=$(pwd) && rm -rf "$DIR"`,
			},
			{
				name: "unknown var in write path",
				cmd:  `rm -rf "$UNKNOWN_DIR"`,
			},
			{
				name: "var with default operator unresolvable",
				cmd:  `rm -rf "${DIR:-/etc}"`,
			},
			{
				name: "var with substitution operator unresolvable",
				cmd:  `rm -rf "${DIR:+/etc}"`,
			},
			{
				name: "indirect var unresolvable",
				cmd:  `rm -rf "${!REF}"`,
			},
			{
				name: "subshell does not propagate var",
				cmd:  "(DIR=/tmp/safe) && rm -rf \"$DIR\"",
			},
			{
				name: "resolvable var in command position still blocked",
				cmd:  `CMD="git" && $CMD status`,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if Evaluate(tt.cmd, testCwd, testRuleSet) {
					t.Errorf("expected FALL-THROUGH for %q", tt.cmd)
				}
			})
		}
	})
}

func TestEvaluate_WriteThenExecute(t *testing.T) {
	t.Run("fall_through", func(t *testing.T) {
		tests := []struct {
			name string
			cmd  string
		}{
			{
				name: "redirect then execute same path",
				cmd:  `echo '#!/bin/bash' > /tmp/evil.sh && /tmp/evil.sh`,
			},
			{
				name: "redirect then execute relative",
				cmd:  "echo '#!/bin/bash' > script.sh && ./script.sh",
			},
			{
				name: "append redirect then execute",
				cmd:  `echo '#!/bin/bash' >> /tmp/evil.sh && /tmp/evil.sh`,
			},
			{
				name: "var-resolved redirect then execute",
				cmd:  `F="/tmp/evil.sh" && echo '#!/bin/bash' > "$F" && /tmp/evil.sh`,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if Evaluate(tt.cmd, testCwd, testRuleSet) {
					t.Errorf("expected FALL-THROUGH for %q", tt.cmd)
				}
			})
		}
	})

	t.Run("allow", func(t *testing.T) {
		tests := []struct {
			name string
			cmd  string
		}{
			{
				name: "redirect without subsequent execute",
				cmd:  `echo data > /tmp/output.txt && echo done`,
			},
			{
				name: "redirect in subshell does not leak",
				cmd:  `(echo data > /tmp/evil.sh) && echo done`,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if !Evaluate(tt.cmd, testCwd, testRuleSet) {
					t.Errorf("expected ALLOW for %q", tt.cmd)
				}
			})
		}
	})
}

func TestEvaluate_Empty(t *testing.T) {
	if Evaluate("", testCwd, testRuleSet) {
		t.Error("empty command should fall through")
	}
	if Evaluate("   ", testCwd, testRuleSet) {
		t.Error("whitespace command should fall through")
	}
}
