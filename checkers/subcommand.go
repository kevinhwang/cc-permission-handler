package checkers

import (
	"strings"

	"cc-permission-handler/check"

	"mvdan.cc/sh/v3/syntax"
)

// subcommandChecker restricts commands to specific first-argument subcommands.
type subcommandChecker struct {
	allowed map[string]bool
}

func (c *subcommandChecker) Check(_ *check.Context, args []*syntax.Word) bool {
	for _, arg := range args[1:] {
		s, ok := check.LiteralString(arg)
		if !ok {
			return false
		}
		if strings.HasPrefix(s, "-") {
			continue
		}
		return c.allowed[s]
	}
	return true
}

func init() {
	check.Register(&subcommandChecker{allowed: check.ToSet(
		"pr", "issue", "repo", "api", "dbx",
		"run", "workflow", "release", "gist",
		"auth", "config", "status",
		"browse", "codespace", "label", "project",
	)}, "gh")

	check.Register(&subcommandChecker{allowed: check.ToSet(
		"build", "test", "bench", "run", "check", "clean", "doc",
		"new", "init", "add", "remove", "fetch", "update", "search",
		"publish", "install", "uninstall", "fix", "clippy", "fmt",
		"tree", "version", "metadata",
	)}, "cargo")

	check.Register(&subcommandChecker{allowed: check.ToSet(
		"install", "ci", "test", "run", "build", "start", "lint",
		"list", "ls", "view", "info", "outdated", "audit",
		"config", "version", "pack", "help", "cache",
		"init", "publish", "link", "unlink", "prune",
		"dedupe", "update", "rebuild", "prefix", "root", "bin",
	)}, "npm")

	check.Register(&subcommandChecker{allowed: check.ToSet(
		"install", "add", "remove", "run", "build", "test", "start",
		"lint", "list", "info", "outdated", "audit",
		"config", "version", "pack", "why", "cache",
		"init", "link", "unlink", "publish", "upgrade",
		"workspace", "workspaces",
	)}, "yarn")

	check.Register(&subcommandChecker{allowed: check.ToSet(
		"install", "add", "remove", "run", "build", "test", "start",
		"lint", "list", "info", "outdated", "audit",
		"config", "version", "pack", "why", "cache",
		"store", "fetch", "dedupe", "link", "unlink",
		"publish", "update", "rebuild",
	)}, "pnpm")

	check.Register(&subcommandChecker{allowed: check.ToSet(
		"install", "add", "remove", "run", "build", "test", "start",
		"lint", "pm", "link", "unlink", "update",
	)}, "bun")

	pipSubs := check.ToSet(
		"install", "uninstall", "download", "list", "show",
		"freeze", "check", "config", "cache", "index",
		"inspect", "search", "wheel", "hash",
	)
	check.Register(&subcommandChecker{allowed: pipSubs}, "pip")
	check.Register(&subcommandChecker{allowed: pipSubs}, "pip3")
}
