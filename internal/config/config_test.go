package config

import (
	"os"
	"path/filepath"
	"testing"

	configpb "cc-permission-handler/internal/gen/config/v1"

	"google.golang.org/protobuf/proto"
)

func TestLoadEmpty(t *testing.T) {
	t.Setenv(envConfigPath, "/nonexistent/config.txtpb")
	if err := Load(); err != nil {
		t.Fatalf("Load with missing file should not error, got: %v", err)
	}
	c := Global()
	if len(c.Projects) != 0 {
		t.Errorf("empty config should have no projects, got %d", len(c.Projects))
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.txtpb")
	content := `
projects {
  path_patterns: "/**"
  allow_write_patterns: "/tmp/**"
}
projects {
  path_patterns: "/home/user/src/server/**"
  allow_project_write: true
  remote_hosts {
    host_patterns: "example.com"
    host_patterns: "*.example.com"
    allow_write_patterns: "/tmp/**"
    allow_write_patterns: "/home/user/src/server/**"
  }
}
`
	os.WriteFile(cfgPath, []byte(content), 0644)
	t.Setenv(envConfigPath, cfgPath)

	if err := Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	c := Global()
	if len(c.Projects) != 2 {
		t.Fatalf("expected 2 projects, got %d", len(c.Projects))
	}
	if !c.Projects[1].GetAllowProjectWrite() {
		t.Error("second project should have AllowProjectWrite")
	}
	if len(c.Projects[1].RemoteHosts) != 1 {
		t.Fatalf("expected 1 remote host entry, got %d", len(c.Projects[1].RemoteHosts))
	}
}

func TestIsWriteAllowed(t *testing.T) {
	c := &configpb.Config{
		Projects: []*configpb.Project{
			{
				PathPatterns:       []string{"/**"},
				AllowWritePatterns: []string{"/tmp/**"},
			},
			{
				PathPatterns:       []string{"/home/user/src/server/**"},
				AllowProjectWrite:  proto.Bool(true),
				AllowWritePatterns: []string{"/var/data/**"},
			},
		},
	}

	tests := []struct {
		name  string
		path  string
		cwd   string
		allow bool
	}{
		{name: "/tmp from anywhere", path: "/tmp/file.txt", cwd: "/home/user/other", allow: true},
		{name: "/tmp nested", path: "/tmp/deep/file", cwd: "/", allow: true},
		{name: "/etc denied", path: "/etc/passwd", cwd: "/home/user", allow: false},
		{name: "project write", path: "/home/user/src/server/output.txt", cwd: "/home/user/src/server", allow: true},
		{name: "project subdir write", path: "/home/user/src/server/pkg/file", cwd: "/home/user/src/server", allow: true},
		{name: "project write from subdir cwd", path: "/home/user/src/server/file", cwd: "/home/user/src/server/pkg", allow: true},
		{name: "project write parent dir", path: "/home/user/src/server/other/file", cwd: "/home/user/src/server/pkg", allow: true},
		{name: "/var/data from server project", path: "/var/data/file", cwd: "/home/user/src/server", allow: true},
		{name: "/var/data from other cwd", path: "/var/data/file", cwd: "/home/user/other", allow: false},
		{name: "outside project", path: "/home/user/other/file", cwd: "/home/user/src/server", allow: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isWriteAllowed(c, tt.path, tt.cwd); got != tt.allow {
				t.Errorf("isWriteAllowed(%q, cwd=%q) = %v, want %v", tt.path, tt.cwd, got, tt.allow)
			}
		})
	}
}

func TestMatchRemoteHost(t *testing.T) {
	c := &configpb.Config{
		Projects: []*configpb.Project{
			{
				PathPatterns: []string{"/**"},
			},
			{
				PathPatterns: []string{"/home/user/src/server/**"},
				RemoteHosts: []*configpb.RemoteHost{
					{
						HostPatterns:       []string{"example.com", "*.example.com"},
						AllowWritePatterns: []string{"/tmp/**"},
					},
				},
			},
		},
	}

	tests := []struct {
		name  string
		host  string
		cwd   string
		found bool
	}{
		{name: "exact match", host: "example.com", cwd: "/home/user/src/server", found: true},
		{name: "wildcard match", host: "foo.example.com", cwd: "/home/user/src/server", found: true},
		{name: "no match host", host: "evil.com", cwd: "/home/user/src/server", found: false},
		{name: "right host wrong cwd", host: "example.com", cwd: "/home/user/other", found: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := matchRemoteHost(c, tt.host, tt.cwd)
			if ok != tt.found {
				t.Errorf("matchRemoteHost(%q, cwd=%q) found = %v, want %v", tt.host, tt.cwd, ok, tt.found)
			}
		})
	}
}

func TestUnionSemantics(t *testing.T) {
	c := &configpb.Config{
		Projects: []*configpb.Project{
			{
				PathPatterns:       []string{"/**"},
				AllowWritePatterns: []string{"/tmp/**"},
			},
			{
				PathPatterns:      []string{"/home/user/src/server/**"},
				AllowProjectWrite: proto.Bool(true),
			},
		},
	}

	cwd := "/home/user/src/server"
	if !isWriteAllowed(c, "/tmp/file", cwd) {
		t.Error("/tmp should be allowed via first project")
	}
	if !isWriteAllowed(c, "/home/user/src/server/file", cwd) {
		t.Error("project dir should be allowed via second project")
	}
	if isWriteAllowed(c, "/etc/passwd", cwd) {
		t.Error("/etc should be denied by both projects")
	}
}

func TestSetGlobal(t *testing.T) {
	c := &configpb.Config{
		Projects: []*configpb.Project{{
			PathPatterns:       []string{"/**"},
			AllowWritePatterns: []string{"/custom/**"},
		}},
	}
	SetGlobal(c)
	if len(Global().Projects) != 1 {
		t.Error("SetGlobal did not update global config")
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		match   bool
	}{
		{name: "doublestar", pattern: "/tmp/**", path: "/tmp/deep/file", match: true},
		{name: "exact", pattern: "/tmp/file", path: "/tmp/file", match: true},
		{name: "no match", pattern: "/tmp/**", path: "/etc/file", match: false},
		{name: "single star", pattern: "/tmp/*", path: "/tmp/file", match: true},
		{name: "single star no depth", pattern: "/tmp/*", path: "/tmp/a/b", match: false},
		{name: "question mark", pattern: "/tmp/?.txt", path: "/tmp/a.txt", match: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GlobMatch(tt.pattern, tt.path); got != tt.match {
				t.Errorf("GlobMatch(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.match)
			}
		})
	}
}
