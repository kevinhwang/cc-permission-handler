package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	_ "cc-permission-handler/checkers"
	"cc-permission-handler/prefer"
	"cc-permission-handler/walker"
)

func runHookTest(t *testing.T, command, cwd string) (allowed bool, output string) {
	t.Helper()
	return runFullHookTest(t, command, cwd, "")
}

type verdict int

const (
	verdictAllow verdict = iota
	verdictDeny
	verdictFallThrough
)

func runFullHookTest(t *testing.T, command, cwd, description string) (allowed bool, output string) {
	t.Helper()

	input := HookInput{
		ToolName:  "Bash",
		ToolInput: ToolInput{Command: command, Description: description},
		Cwd:       cwd,
	}
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}

	parsed, err := readInput(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("readInput: %v", err)
	}
	if parsed.ToolName != "Bash" {
		return false, ""
	}

	cmd := parsed.ToolInput.Command
	if cmd == "" {
		return false, ""
	}

	f, err := walker.ParseCommand(cmd)
	if err != nil || len(f.Stmts) == 0 {
		return false, ""
	}

	var stdout bytes.Buffer

	if !prefer.HasSuppressPrefix(parsed.ToolInput.Description) {
		if msg, deny := prefer.CheckPreferBuiltin(f); deny {
			writeDeny(&stdout, msg)
			return false, stdout.String()
		}
	}

	if walker.EvaluateAST(f, parsed.Cwd, nil) {
		writeAllow(&stdout)
		return true, stdout.String()
	}

	return false, ""
}

func getVerdict(t *testing.T, command, cwd, description string) verdict {
	t.Helper()
	allowed, output := runFullHookTest(t, command, cwd, description)
	if allowed {
		return verdictAllow
	}
	if output != "" {
		return verdictDeny
	}
	return verdictFallThrough
}

func TestIntegration_RoundTrip(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		allowed, output := runHookTest(t, "cd dir && git status", "/project")
		if !allowed {
			t.Fatal("expected allow")
		}
		var result HookOutput
		if err := json.Unmarshal([]byte(output), &result); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if result.HookSpecificOutput.HookEventName != "PermissionRequest" {
			t.Errorf("hookEventName = %q", result.HookSpecificOutput.HookEventName)
		}
		if result.HookSpecificOutput.Decision.Behavior != "allow" {
			t.Errorf("behavior = %q", result.HookSpecificOutput.Decision.Behavior)
		}
	})

	t.Run("fall-through", func(t *testing.T) {
		allowed, output := runHookTest(t, "rm -rf /", "/project")
		if allowed {
			t.Fatal("expected fall-through")
		}
		if output != "" {
			t.Errorf("expected empty stdout, got %q", output)
		}
	})
}

func TestIntegration_OutputFormat(t *testing.T) {
	_, output := runHookTest(t, "git status", "/project")
	var raw map[string]any
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(raw) != 1 {
		t.Errorf("expected 1 top-level key, got %v", raw)
	}
	hso := raw["hookSpecificOutput"].(map[string]any)
	if len(hso) != 2 {
		t.Errorf("expected 2 keys in hookSpecificOutput, got %v", hso)
	}
	decision := hso["decision"].(map[string]any)
	if len(decision) != 1 {
		t.Errorf("expected 1 key in decision, got %v", decision)
	}
}

func TestIntegration_NonBashTool(t *testing.T) {
	input := HookInput{
		ToolName:  "Write",
		ToolInput: ToolInput{Command: "anything"},
		Cwd:       "/project",
	}
	payload, _ := json.Marshal(input)
	parsed, _ := readInput(bytes.NewReader(payload))
	if parsed.ToolName == "Bash" {
		t.Fatal("should not be Bash")
	}
}

func TestIntegration_MalformedJSON(t *testing.T) {
	_, err := readInput(strings.NewReader("{invalid json"))
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestIntegration_EmptyCommand(t *testing.T) {
	allowed, _ := runHookTest(t, "", "/project")
	if allowed {
		t.Error("empty command should fall through")
	}
}

func TestIntegration_NoCwd(t *testing.T) {
	t.Run("file redirect denied", func(t *testing.T) {
		if allowed, _ := runHookTest(t, "git log > output.txt", ""); allowed {
			t.Error("should fall through without cwd")
		}
	})
	t.Run("dev null still works", func(t *testing.T) {
		if allowed, _ := runHookTest(t, "git log > /dev/null", ""); !allowed {
			t.Error("should allow /dev/null without cwd")
		}
	})
}

func TestIntegration_CombinedLayers(t *testing.T) {
	const cwd = "/project"

	t.Run("simple grep → deny prefer", func(t *testing.T) {
		if v := getVerdict(t, "grep pattern file", cwd, ""); v != verdictDeny {
			t.Errorf("expected deny, got %v", v)
		}
	})
	t.Run("simple grep with suppress → allow", func(t *testing.T) {
		if v := getVerdict(t, "grep pattern file", cwd, prefer.SuppressPrefix+" searching"); v != verdictAllow {
			t.Errorf("expected allow, got %v", v)
		}
	})
	t.Run("cd && cat → deny prefer", func(t *testing.T) {
		if v := getVerdict(t, "cd dir && cat file.txt", cwd, ""); v != verdictDeny {
			t.Errorf("expected deny, got %v", v)
		}
	})
	t.Run("cd && git status → allow", func(t *testing.T) {
		if v := getVerdict(t, "cd dir && git status", cwd, ""); v != verdictAllow {
			t.Errorf("expected allow, got %v", v)
		}
	})
	t.Run("cat | grep → deny (pipeline of preferred tools)", func(t *testing.T) {
		if v := getVerdict(t, "cat file | grep pattern", cwd, ""); v != verdictDeny {
			t.Errorf("expected deny, got %v", v)
		}
	})
	t.Run("unknown_cmd → fall-through", func(t *testing.T) {
		if v := getVerdict(t, "unknown_cmd arg", cwd, ""); v != verdictFallThrough {
			t.Errorf("expected fall-through, got %v", v)
		}
	})
	t.Run("find with suppress → allow", func(t *testing.T) {
		if v := getVerdict(t, "find . -name '*.go'", cwd, prefer.SuppressPrefix+" need find"); v != verdictAllow {
			t.Errorf("expected allow, got %v", v)
		}
	})
	t.Run("deny message has correct JSON structure", func(t *testing.T) {
		_, output := runFullHookTest(t, "cat file.txt", cwd, "")
		var result HookOutput
		if err := json.Unmarshal([]byte(output), &result); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if result.HookSpecificOutput.Decision.Behavior != "deny" {
			t.Errorf("behavior = %q, want deny", result.HookSpecificOutput.Decision.Behavior)
		}
		if result.HookSpecificOutput.Decision.Message == "" {
			t.Error("deny message should not be empty")
		}
	})
}
