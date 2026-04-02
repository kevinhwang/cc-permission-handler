# cc-permission-handler

[![CI](https://github.com/kevinhwang/cc-permission-handler/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kevinhwang/cc-permission-handler/actions/workflows/ci.yml)

A Claude Code [PermissionRequest hook](https://code.claude.com/docs/en/hooks#permissionrequest) that reduces permission prompt friction for common, safe-*ish*<sup>*</sup> bash commands while steering Claude toward better native tools when appropriate.

## Motivation

Claude Code's default permission system is very conservative with compound bash commands. A simple `cd dir && git status` triggers a permission prompt because the built-in pattern matching can't verify compound commands joined by `&&`, `||`, pipes, etc. This is safe but slow — you end up approving dozens of obviously-safe commands per session.

Many users end up running Claude with `--dangerously-skip-permissions` out of permission weariness. This is intended to trade some marginal safety for convenience and autonomy.

This hook sits between Claude and the default permission prompt. It auto-approves commands that should *almost always*<sup>*</sup> be safe (but importantly, does not try to prevent every possible dangerous bypass), denies commands that should use native tools instead, and falls through to the normal user permission prompt for everything else.

## * Not A Security Tool ‼️

This tool is **not** a security boundary. It does not make Claude Code more safe, but *less* as it opens up the door in exchange for some convenience.

Think of this as an *auto-approver* for many common bash workflow patterns Claude tends to use. It does not perfectly block all possible dangerous Bash usage, though it tries to account for the most common ones. See [Limitations](#limitations) below for more details.

ℹ️ The threat model should be thought of as an honest Claude who occasionally makes simple mistakes or typos, and which is generally assumed to be already hardened against indirect prompt injections.

⚠️ Seriously unhinged hallucinations or novel IPI vectors could potentially cause Claude to execute a dangerous Bash workflow that gets approved by this hook.
Use at your own risk!

## Workflow

The hook processes each Bash tool request through two layers, in order:

### 1. Prefer Native Tools (Deny + Steer)

Claude has a strong tendency to reach for bash utilities (`cat`, `grep`, `find`,`sed`, etc.) when Claude Code's built-in tools (`Read`, `Grep`, `Glob`, `Edit`) would be better. See [anthropics/claude-code#19649](https://github.com/anthropics/claude-code/issues/19649).

This layer detects **simple, trivial** uses of these commands — e.g., `cat file.txt`, `grep pattern file`, `cat file | head -10` — and denies them with a message telling Claude which native tool to use instead.

The deny message includes an escape hatch: Claude can retry with `[SUPPRESS_PREFER_TOOL_WARNING]` in the Bash tool's description field if it genuinely needs bash for the task. This lets Claude self-correct on the rare occasions the suggestion is wrong.

### 2. Safety Evaluation (Allow or Fall-Through)

Commands that pass Layer 1 (or bypass it via suppression) are parsed into a full Bash AST using [mvdan/sh](https://github.com/mvdan/sh) and recursively checked for safety.

The AST is walked node by node. Every component of the command — each statement in a compound chain, each side of a pipe, the condition and body of `if`/`for`/`while`/`case` blocks, the contents of subshells and brace groups, even command substitutions nested inside arguments — is checked independently and recursively.

**What gets approved:**

- Commands whose executable is in a curated safe list (read-only utilities, shell builtins, specific build tools)
- Commands with subcommand restrictions (e.g., `git status` is allowed but `npm exec` is not)
- `git config` in read-only mode (`--get`, `--list`, key lookup); config writes fall through
- `go run` with project-local targets; absolute paths outside the project fall through
- Commands that write to files, but only when every target path resolves to within the project's working directory or configured allowed directories
- `ssh` / `tsh` commands to configured remote hosts, where the remote command is extracted and evaluated with the same rules using per-host allowed write directories
- `env` / `command` wrapping a safe inner command, `find`/`fd` without `-exec`/`-delete`, `awk` without `system()`/`getline`, `sed` without `e`/`w`/`W` commands

**What causes fall-through** (to Claude Code's default permission prompt):

- Unknown or unrecognized commands
- Commands with dangerous flags (`git -c` which can set arbitrary config, `ssh -o` which can set ProxyCommand, `sed -i` which writes in place)
- Expansions or substitutions in positions where output would be interpreted as code (command names, `env` inner commands, redirect targets, `awk` program text, etc.)
- Background execution, function definitions, `eval`, `exec`, `source`, coprocesses

### Fall Through To Claude Code Default Permissions Prompt

Anything the hook doesn't explicitly allow or deny falls through to Claude Code's normal permission dialog, where you approve or reject manually. The hook never blocks anything that Claude Code would otherwise allow — it only adds auto-approvals and native-tool suggestions on top.

## Limitations

This is a best-effort convenience tool, not a security boundary. It aims to be good enough to automate the approval of the vast majority of safe commands Claude generates, while catching the obvious dangerous ones. It is not immune to:

- **Build-tool code execution**: Commands like `cargo build`, `npm install`, or `go test` are allowed because they're standard development operations, but they execute build scripts, lifecycle hooks, and test code that could do anything. A malicious dependency or a sufficiently confused Claude could exploit this.
- **Clever multi-step attacks**: A prompt injection that first creates a malicious script in an allowed write dir, then executes it in a subsequent command, could bypass the per-command analysis. The hook evaluates each command in isolation.
- **Interpreter arguments**: Build tools and compilers (`rustc`, `tsc`, `eslint`) process project files that could theoretically contain malicious code triggered by compilation.

The hook reduces friction for the common case while keeping Claude Code's manual approval as the backstop for anything unusual.

## Configuration

User-specific settings are in a [textproto](https://protobuf.dev/reference/protobuf/textformat-spec/) config file at `~/.config/cc-permission-handler/config.txtpb` (override path with `CC_PERMISSION_HANDLER_CONFIG` env var). The schema is defined in [`proto/config/v1/config.proto`](proto/config/v1/config.proto).

```textproto
# Any invocation of Claude in any cwd can write to /tmp/.
projects {
  path_patterns: "/**"
  allow_write_patterns: "/tmp/**"
}

# Claude in the server project can write to its own directory
# and ssh/tsh to specific remote hosts.
projects {
  path_patterns: "~/src/server/**"
  allow_project_write: true

  remote_hosts {
    host_patterns: "myhost.example.com"
    host_patterns: "*.example.com"
    allow_write_patterns: "~/src/server/**"
    allow_write_patterns: "/tmp/**"
  }
}
```

Rules are project-scoped. Each project entry matches by `path_patterns` (glob) against the hook's working directory. All matching projects are evaluated — if any project's rules allow a write, it's allowed.

- **`path_patterns`**: Glob patterns (`*`, `?`, `**`) matched against cwd. `~` expanded locally.
- **`allow_write_patterns`**: Glob patterns for paths where writes are allowed. `~` expanded locally.
- **`allow_project_write`**: If true, writes anywhere the project's `path_patterns` match are allowed.
- **`remote_hosts`**: SSH/tsh destinations and their allowed remote write paths. Remote `allow_write_patterns` are matched literally (no local `~` expansion — use `~` in the pattern if the remote command uses `~`).

If no config file exists, nothing is auto-approved for writes (most restrictive). Read-only commands still work.

Command safety rules (safe commands list, subcommand allowlists, dangerous flag detection, etc.) are defined in Go source in the `checkers/` package and are not user-configurable.

## Setup

Install the binary:

```shell
make build
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

If the binary isn't on your `PATH`, use the full path (e.g. `~/go/bin/cc-permission-handler`).

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
