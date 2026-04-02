package prefer

import (
	"strings"
	"testing"

	"cc-permission-handler/walker"
)

func parseAndCheckPrefer(t *testing.T, cmd string) (string, bool) {
	t.Helper()
	f, err := walker.ParseCommand(cmd)
	if err != nil {
		t.Fatalf("parse %q: %v", cmd, err)
	}
	return CheckPreferBuiltin(f)
}

func TestPrefer_SimpleTriggers(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		tool string
	}{
		{name: "cat", cmd: "cat file.txt", tool: "Read"},
		{name: "cat with flags", cmd: "cat -n file.txt", tool: "Read"},
		{name: "head", cmd: "head -20 file.txt", tool: "Read"},
		{name: "tail", cmd: "tail -f file.txt", tool: "Read"},
		{name: "sed", cmd: "sed 's/foo/bar/' file.txt", tool: "Edit"},
		{name: "awk", cmd: "awk '{print $1}' file.txt", tool: "Edit"},
		{name: "gawk", cmd: "gawk '/pattern/' file.txt", tool: "Edit"},
		{name: "grep", cmd: "grep -r pattern src/", tool: "Grep"},
		{name: "egrep", cmd: "egrep 'a|b' file", tool: "Grep"},
		{name: "fgrep", cmd: "fgrep literal file", tool: "Grep"},
		{name: "rg", cmd: "rg pattern src/", tool: "Grep"},
		{name: "find", cmd: "find . -name '*.go'", tool: "Glob"},
		{name: "cat with redirect", cmd: "cat file.txt 2>/dev/null", tool: "Read"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, deny := parseAndCheckPrefer(t, tt.cmd)
			if !deny {
				t.Errorf("expected deny for %q", tt.cmd)
				return
			}
			if !strings.Contains(msg, tt.tool) {
				t.Errorf("message %q should mention %q", msg, tt.tool)
			}
			if !strings.Contains(msg, SuppressPrefix) {
				t.Errorf("message should include suppress prefix instructions")
			}
		})
	}
}

func TestPrefer_CdCompound(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		deny bool
	}{
		{name: "cd && cat", cmd: "cd dir && cat file.txt", deny: true},
		{name: "cd && grep", cmd: "cd src && grep pattern file", deny: true},
		{name: "cd && find", cmd: "cd /project && find . -name '*.go'", deny: true},
		{name: "cd && git", cmd: "cd dir && git status", deny: false},
		{name: "cd && echo", cmd: "cd dir && echo hello", deny: false},
		{name: "cd && cat pipe", cmd: "cd dir && cat file | grep pat", deny: true},
		{name: "cd && cat && echo", cmd: "cd dir && cat file && echo done", deny: false},
		{name: "cd && cat || fallback", cmd: "cd dir && cat file || echo 'not found'", deny: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, deny := parseAndCheckPrefer(t, tt.cmd)
			if deny != tt.deny {
				t.Errorf("CheckPreferBuiltin(%q) deny = %v, want %v", tt.cmd, deny, tt.deny)
			}
		})
	}
}

func TestPrefer_OrFallback(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		deny bool
	}{
		{name: "cat || echo", cmd: "cat file || echo 'not found'", deny: true},
		{name: "cat 2>/dev/null || echo", cmd: "cat file 2>/dev/null || echo 'not found'", deny: true},
		{name: "grep || true", cmd: "grep pattern file || true", deny: true},
		{name: "head || echo", cmd: "head -20 file || echo 'empty'", deny: true},
		{name: "cat || echo || echo", cmd: "cat file || echo a || echo b", deny: true},
		{name: "git || echo", cmd: "git status || echo 'not a repo'", deny: false},
		{name: "echo || true", cmd: "echo hello || true", deny: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, deny := parseAndCheckPrefer(t, tt.cmd)
			if deny != tt.deny {
				t.Errorf("CheckPreferBuiltin(%q) deny = %v, want %v", tt.cmd, deny, tt.deny)
			}
		})
	}
}

func TestPrefer_PipeTriggers(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		tool string
	}{
		{name: "cat | head", cmd: "cat file | head -10", tool: "Read"},
		{name: "cat | tail", cmd: "cat file | tail -5", tool: "Read"},
		{name: "cat | grep", cmd: "cat file | grep pattern", tool: "Grep"},
		{name: "cat | head | tail", cmd: "cat file | head -20 | tail -5", tool: "Read"},
		{name: "cat | head with flags", cmd: "cat -n file | head -10", tool: "Read"},
		{name: "cd && cat | head", cmd: "cd dir && cat file | head -10", tool: "Read"},
		{name: "cat | head || fallback", cmd: "cat file | head -10 || echo empty", tool: "Read"},
		{name: "cd && cat | head || fallback", cmd: "cd dir && cat file | head -10 || echo empty", tool: "Read"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, deny := parseAndCheckPrefer(t, tt.cmd)
			if !deny {
				t.Errorf("expected deny for %q", tt.cmd)
				return
			}
			if !strings.Contains(msg, tt.tool) {
				t.Errorf("message %q should mention %q", msg, tt.tool)
			}
			if !strings.Contains(msg, SuppressPrefix) {
				t.Errorf("message should include suppress prefix instructions")
			}
		})
	}
}

func TestPrefer_PipeNoTrigger(t *testing.T) {
	cmds := []string{
		"cat file | sort",
		"cat file | wc -l",
		"ls | grep pattern",
		"cat file | head -10 | wc -l",
		"cmd1 | cmd2 | cmd3 | cmd4",
		"echo hello | cat | head | tail",
	}
	for _, cmd := range cmds {
		t.Run(cmd, func(t *testing.T) {
			_, deny := parseAndCheckPrefer(t, cmd)
			if deny {
				t.Errorf("should not trigger for pipe %q", cmd)
			}
		})
	}
}

func TestPrefer_CompoundNoTrigger(t *testing.T) {
	cmds := []string{
		"cat file && echo done",
		"cat file; echo done",
		"cat a && cat b",
	}
	for _, cmd := range cmds {
		t.Run(cmd, func(t *testing.T) {
			_, deny := parseAndCheckPrefer(t, cmd)
			if deny {
				t.Errorf("should not trigger for compound %q", cmd)
			}
		})
	}
}

func TestPrefer_ControlFlowNoTrigger(t *testing.T) {
	cmds := []string{
		`for f in *.txt; do cat "$f"; done`,
		"if grep -q pattern file; then echo found; fi",
		"while read line; do echo $line; done",
		"(cat file.txt)",
		"{ cat file.txt; }",
	}
	for _, cmd := range cmds {
		t.Run(cmd, func(t *testing.T) {
			_, deny := parseAndCheckPrefer(t, cmd)
			if deny {
				t.Errorf("should not trigger for control flow %q", cmd)
			}
		})
	}
}

func TestPrefer_NonPreferredNoTrigger(t *testing.T) {
	cmds := []string{"git status", "echo hello", "ls -la", "unknown_cmd arg", "npm install"}
	for _, cmd := range cmds {
		t.Run(cmd, func(t *testing.T) {
			_, deny := parseAndCheckPrefer(t, cmd)
			if deny {
				t.Errorf("should not trigger for non-preferred %q", cmd)
			}
		})
	}
}

func TestPrefer_BackgroundNoTrigger(t *testing.T) {
	_, deny := parseAndCheckPrefer(t, "cat file &")
	if deny {
		t.Error("should not trigger for background command")
	}
}

func TestHasSuppressPrefix(t *testing.T) {
	tests := []struct {
		desc     string
		suppress bool
	}{
		{desc: "", suppress: false},
		{desc: "some description", suppress: false},
		{desc: "[SUPPRESS_PREFER_TOOL_WARNING] need bash for this", suppress: true},
		{desc: "prefix [SUPPRESS_PREFER_TOOL_WARNING] middle", suppress: true},
	}
	for _, tt := range tests {
		if got := HasSuppressPrefix(tt.desc); got != tt.suppress {
			t.Errorf("HasSuppressPrefix(%q) = %v, want %v", tt.desc, got, tt.suppress)
		}
	}
}
