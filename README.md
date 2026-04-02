# cc-permission-handler

[![CI](https://github.com/kevinhwang/cc-permission-handler/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kevinhwang/cc-permission-handler/actions/workflows/ci.yml)

A Claude Code [PermissionRequest hook](https://code.claude.com/docs/en/hooks#permissionrequest) that reduces permission prompt friction for common, safe-*ish*<sup>*</sup> bash commands while optionally steering Claude toward better native tools when appropriate.

## Motivation

Claude Code's default permission system is very conservative even when you configure a comprehensive allowlist of Bash commands. A simple `cd dir && git status` triggers a permission prompt because the built-in pattern matching can't verify compound commands joined by `&&`, `||`, pipes, etc. It also can't parse and verify as safe multi-line scripts, conditional expressions, reason about redirects, etc., so it ends up prompting you constantly. This is safe but slow — you end up approving dozens of obviously-safe commands per session.

Many users end up running Claude with `--dangerously-skip-permissions` out of permission fatigue. This hook is a better option than *that*, while still being better option than otherwise babying Claude and having to approve every little harmless command. It's intended to trade some marginal safety for convenience and autonomy.

It's not as sophisticated as Claude's ["auto mode"](https://www.anthropic.com/engineering/claude-code-auto-mode), but auto mode is [only available through a Claude Code subscription](https://code.claude.com/docs/en/permission-modes#eliminate-prompts-with-auto-mode), not when using Claude with model providers like Amazon Bedrock.

This hook sits between Claude and the default permission prompt. It auto-approves commands that should *almost always*<sup>*</sup> be safe, optionally denies commands that should use native tools instead, and falls through to the normal user permission prompt for everything else.

## * Not A Security Tool ‼️

This tool is **not** a security boundary. It does not make Claude Code more safe, but slightly *less* so as it loosens up Claude in exchange for some convenience.

Think of this as an *auto-approver* for many common bash workflow patterns Claude tends to use. It does not perfectly block all possible dangerous Bash usage, though it tries to account for the most common ones. See [Limitations](#limitations) below for more details.

ℹ️ The threat model should be thought of as an honest Claude who occasionally makes simple mistakes or typos, and which is generally assumed to be already hardened against indirect prompt injections.

⚠️ Though unlikely, seriously unhinged hallucinations or novel IPI vectors could potentially cause Claude to execute a dangerous Bash workflow that gets approved by this hook. Use at your own risk!

## Default Approval Workflow

The hook processes each Bash tool request through two layers, in order:

### 1. Prefer Native Tools (Deny + Steer) — Optional

Claude Code has a strong tendency to reach for bash utilities (`cat`, `grep`, `find`, `sed`, etc.) when Claude's built-in tools (`Read`, `Grep`, `Glob`, `Edit`) would be better. See [anthropics/claude-code#19649](https://github.com/anthropics/claude-code/issues/19649).

When enabled in the config, this layer detects **simple, trivial** uses of these commands — e.g., `cat file.txt`, `grep pattern file`, `cat file | head -10` — and denies them with a message telling Claude which native tool to use instead.

The deny message includes an escape hatch: Claude can retry with `[SUPPRESS_PREFER_TOOL_WARNING]` in the Bash tool's description field if it genuinely needs bash for the task.

This layer is disabled by default and must be opted into.

### 2. Safety Evaluation (Allow or Fall-Through)

Commands that pass Layer 1 are parsed into a full Bash AST using [mvdan/sh](https://github.com/mvdan/sh) and recursively checked for safety using a config-driven rule engine.

The AST is walked node by node. Every component of the command — each statement in a compound chain, each side of a pipe, the condition and body of `if`/`for`/`while`/`case` blocks, the contents of subshells and brace groups, even command substitutions nested inside arguments — is checked independently and recursively.

Each command is looked up in the configured rule set and evaluated against its rules. The built-in default rules cover common development tools:

**What gets approved (with default rules):**

- Read-only utilities and shell builtins (`cat`, `ls`, `grep`, `jq`, `cd`, `echo`, `test`, etc.)
- Commands with subcommand restrictions (e.g., `git status` is allowed but unknown git subcommands fall through; `npm install` is allowed but `npm exec` falls through)
- Commands that write to files, but only when every target path resolves to within configured allowed directories
- `ssh` / `tsh` commands to configured remote hosts, where the remote command is recursively evaluated using per-host allowed write directories
- `go run` with project-local targets
- `find`/`fd` without `-exec`/`-delete`, `awk` without `system()`/`getline`, `sed` without `e`/`w`/`W` commands
- `sort -o` and similar write-flag commands, but only when the output path is in an allowed directory

**What causes fall-through** (to Claude Code's default permission prompt):

- Unknown or unrecognized commands
- Commands with dangerous flags (`git -c` which can set arbitrary config, `sed -i` which writes in place, `yq --in-place`, etc.)
- Expansions or substitutions in positions where output would be interpreted as code
- Background execution, function definitions, `eval`, `exec`, `source`, coprocesses

### Fall Through To Claude Code Default Permissions Prompt

Anything the hook doesn't explicitly allow or deny falls through to Claude Code's normal permission dialog, where you approve or reject manually. The hook never blocks anything that Claude Code would otherwise allow — it only adds auto-approvals and native-tool suggestions on top.

## Limitations

This is a best-effort convenience tool, not a security boundary. It aims to be good enough to automate the approval of the vast majority of safe commands Claude generates, while catching the obvious dangerous ones. It is not immune to:

- **Build-tool code execution**: Commands like `cargo build`, `npm install`, or `go test` are allowed because they're standard development operations, but they execute build scripts, lifecycle hooks, and test code that could do anything. A malicious dependency or a sufficiently confused Claude could exploit this.
- **Clever multi-step attacks**: A prompt injection that first creates a malicious script in an allowed write dir, then executes it in a subsequent command, could bypass the per-command analysis. The hook evaluates each command in isolation.
- **Interpreter arguments**: Build tools and compilers (`rustc`, `tsc`, `eslint`) process project files that could theoretically contain malicious code triggered by compilation.

The hook reduces friction for the common case while keeping Claude Code's manual approval as the backstop for anything unusual.

## Setup

The quickest way to get started:

```shell
make install-hook
```

This interactive script will:
1. Install the binary via `go install`
2. Create a starter config at `~/.config/cc-permission-handler/config.txtpb` (if it doesn't exist)
3. Register the hook in `~/.claude/settings.json` (if not already registered)

Each step prompts for confirmation before making changes.

### Manual Setup

If you prefer to set things up manually:

Install the binary:

```shell
make install
```

This will build the binary and install it to your `$GOPATH`.

Create a config file at `~/.config/cc-permission-handler/config.txtpb`:

```txtpb
projects {
  path_patterns: "/**"
  allow_write_patterns: "/tmp/**"
  use_default_rules {}
}
```

Register it in your Claude Code settings (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "PermissionRequest": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "cc-permission-handler"
          }
        ]
      }
    ]
  }
}
```

Ensure your `$GOPATH` is part of your `$PATH` under which `claude` runs. Otherwise, specify the full path in your Claude hook settings.

## Configuration

User-specific settings are in a [text proto](https://protobuf.dev/reference/protobuf/textformat-spec/) config file at `~/.config/cc-permission-handler/config.txtpb` (override path with `CC_PERMISSION_HANDLER_CONFIG` env var). The schema is defined in [`proto/config/v1/config.proto`](proto/config/v1/config.proto).

```txtpb
# (Global) any project:
# - Can write to /tmp
# - Will use default approval rules
# - Will steer Claude toward native tools
projects {
  path_patterns: "/**"
  allow_write_patterns: "/tmp/**"
  use_default_rules {}
  prefer_native_tools: true
}

# Project-specific: Claude in example project can also write to its
# own directory and ssh to configured remote hosts.
projects {
  path_patterns: "~/projects/example/**"
  allow_project_write: true

  remote_hosts {
    host_patterns: "myhost.example.com"
    host_patterns: "*.example.com"
    allow_write_patterns: "/tmp/**"
    allow_write_patterns: "~/src/server/**"
  }
}
```

### Project Settings

Rules are project-scoped. Each project entry matches by `path_patterns` (glob) against the hook's working directory. All matching projects are evaluated — settings are unioned.

| Field | Description |
|---|---|
| `path_patterns` | Glob patterns (`*`, `?`, `**`) matched against cwd. `~` expanded locally. |
| `allow_write_patterns` | Glob patterns for paths where writes are allowed. `~` expanded locally. |
| `allow_project_write` | If true, writes anywhere the project's `path_patterns` match are allowed. |
| `remote_hosts` | SSH/tsh destinations and their allowed remote write paths. |
| `use_default_rules` | Enables the built-in command safety rules (see below). Without this, no commands are auto-approved. |
| `prefer_native_tools` | When true, simple uses of bash utilities (`cat`, `grep`, `find`, `sed`) are denied with suggestions to use Claude Code's native tools instead. |

If no config file exists, nothing is auto-approved (most restrictive).

### Command Rules

The built-in default rules are enabled per-project with `use_default_rules {}`. These cover ~80 common commands with curated safety checks — the behavior described in the [Default Approval Workflow](#default-approval-workflow) section above.

**The rules are fully customizable.** Instead of (or in addition to) the defaults, you can define your own command rules using a `custom_command_rules` DSL in the config. Each command spec has a list of `allow` and `deny` rules with composable conditions:

| Example | Description |
|---|---|
| `allow { condition { always {} } }` | Command is always safe |
| `deny { condition { has_flag_matching { ... } } }` | Deny if a dangerous flag is present |
| `allow { condition { subcommands { ... } } }` | Subcommand allowlist |
| `allow { condition { every_flag_matches { ... } } }` | Only listed flags are permitted |
| `allow { condition { every_positional_passes { ... } } }` | Write-path checking on positional args |
| `allow { condition { not { has_flag_matching { ... } } } }` | Allow unless a flag is present |

and many more...

For a command to be allowed: all rules must pass, and at least one `allow` rule must contribute a positive vote. `deny` rules act as gates — if the deny condition is true, the command is immediately rejected.

For the full rule DSL grammar, see [`proto/rules/v1/rules.proto`](proto/rules/v1/rules.proto).

For a comprehensive example of how to write rules, see the built-in default rules at [`internal/rules/default.txtpb`](internal/rules/default.txtpb).

## Testing

Run the test suite:

```bash
make test
```

Test individual commands via CLI:

```bash
cc-permission-handler --test --cwd=/your/project "cd dir && git status"
cc-permission-handler --test "cat file.txt"
cc-permission-handler --test "unknown_command arg"
```

Test the full JSON pipeline:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"cd dir && git status"},"cwd":"/project"}' | cc-permission-handler
```
