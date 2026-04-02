package checkers

import (
	"strings"

	"cc-permission-handler/check"

	"mvdan.cc/sh/v3/syntax"
)

var gitAllowedSubcommands = check.ToSet(
	"status", "log", "diff", "show", "branch", "tag",
	"stash", "add", "commit", "fetch", "pull", "push",
	"checkout", "switch", "restore", "merge", "rebase",
	"remote", "rev-parse", "ls-files", "ls-tree",
	"blame", "shortlog", "describe", "name-rev",
	"config", "worktree", "submodule", "cherry-pick",
	"clean", "reset", "mv", "rm",
	"init", "clone",
)

var gitDangerousFlags = check.ToSet("-c", "--config-env")
var gitFlagsWithArg = check.ToSet("-C", "--git-dir", "--work-tree", "--namespace")

var gitConfigReadFlags = check.ToSet("--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l")
var gitConfigWriteFlags = check.ToSet("--unset", "--unset-all", "--add", "--replace-all",
	"--rename-section", "--remove-section", "--edit", "-e")
var gitConfigFlagsWithArg = check.ToSet("--file", "--blob", "--type")

type gitChecker struct{}

func (gitChecker) Check(_ *check.Context, args []*syntax.Word) bool {
	i := 1
	for i < len(args) {
		s, ok := check.LiteralString(args[i])
		if !ok {
			return false
		}
		if s == "--" {
			return false
		}
		if strings.HasPrefix(s, "-") && strings.Contains(s, "=") {
			flagPart := s[:strings.Index(s, "=")]
			if gitDangerousFlags[flagPart] {
				return false
			}
		}
		if gitDangerousFlags[s] {
			return false
		}
		if gitFlagsWithArg[s] {
			i += 2
			continue
		}
		if strings.HasPrefix(s, "-") {
			i++
			continue
		}
		if !gitAllowedSubcommands[s] {
			return false
		}
		if s == "config" {
			return isGitConfigReadOnly(args, i+1)
		}
		return true
	}
	return true
}

func isGitConfigReadOnly(args []*syntax.Word, start int) bool {
	positionals := 0
	for i := start; i < len(args); i++ {
		s, ok := check.LiteralString(args[i])
		if !ok {
			return false
		}
		if gitConfigReadFlags[s] {
			return true
		}
		if gitConfigWriteFlags[s] {
			return false
		}
		if gitConfigFlagsWithArg[s] {
			i++
			continue
		}
		if strings.HasPrefix(s, "-") && strings.Contains(s, "=") {
			continue
		}
		if strings.HasPrefix(s, "-") {
			continue
		}
		positionals++
	}
	return positionals <= 1
}

func init() { check.Register(gitChecker{}, "git") }
