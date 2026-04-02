package checkers

import (
	"cc-permission-handler/check"

	"mvdan.cc/sh/v3/syntax"
)

// safeChecker approves commands that are safe with any arguments.
type safeChecker struct{}

func (safeChecker) Check(*check.Context, []*syntax.Word) bool { return true }

// flagCheckedSafe approves commands unless specific write-mode flags are present.
type flagCheckedSafe struct {
	shortChars   string
	longPrefixes []string
}

func (c *flagCheckedSafe) Check(_ *check.Context, args []*syntax.Word) bool {
	return !check.HasWriteFlags(args, c.shortChars, c.longPrefixes...)
}

func init() {
	safe := safeChecker{}
	check.Register(safe,
		// Filesystem inspection
		"cat", "head", "tail", "less", "more", "bat",
		"ls", "tree", "exa", "eza",
		"file", "stat", "du", "df",
		"pwd",
		// Text processing
		"echo", "printf",
		"grep", "egrep", "fgrep", "rg", "ag", "ack",
		"wc", "uniq", "cut", "tr", "rev", "tac",
		"diff", "cmp", "comm", "colordiff", "delta",
		"column", "expand", "fold", "fmt", "nl", "paste", "join",
		// Search / locate
		"locate", "mdfind",
		// Path utilities
		"basename", "dirname", "realpath", "readlink",
		// Checksums
		"md5sum", "sha256sum", "sha1sum", "shasum", "md5",
		// Env / identity
		"printenv",
		"uname", "hostname",
		"id", "whoami", "groups",
		"date", "cal",
		// Structured data
		"jq",
		// Shell builtins / trivial
		"cd", "pushd", "popd", "true", "false", "test", "[",
		"which", "whereis", "type", "hash",
		"seq", "mktemp", "sleep",
		"export", "set",
		// System info (read-only)
		"top", "ps", "uptime", "free",
		// Build tools (purpose-specific)
		"agent-bzl", "bazel", "bzl", "mbzl",
		"rustc",
		"tsc", "eslint", "prettier",
		"black", "isort", "flake8", "mypy", "pylint", "ruff",
		"shellcheck",
	)

	check.Register(&flagCheckedSafe{shortChars: "o", longPrefixes: []string{"--output"}}, "sort")
	check.Register(&flagCheckedSafe{shortChars: "i", longPrefixes: []string{"--in-place"}}, "yq")
}
