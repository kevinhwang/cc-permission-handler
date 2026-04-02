package checkers

import (
	"path/filepath"
	"strings"

	"cc-permission-handler/check"

	"mvdan.cc/sh/v3/syntax"
)

var goAllowedSubcommands = check.ToSet(
	"build", "test", "vet", "fmt", "mod", "get", "install",
	"clean", "env", "version", "list", "doc", "work", "tool",
	"run", "generate",
)

type goChecker struct{}

func (goChecker) Check(ctx *check.Context, args []*syntax.Word) bool {
	for i := 1; i < len(args); i++ {
		s, ok := check.LiteralString(args[i])
		if !ok {
			return false
		}
		if strings.HasPrefix(s, "-") {
			continue
		}
		if !goAllowedSubcommands[s] {
			return false
		}
		if s == "run" {
			return checkGoRun(ctx, args, i+1)
		}
		return true
	}
	return true
}

// checkGoRun validates that go run targets don't reference files outside
// the project directory.
func checkGoRun(ctx *check.Context, args []*syntax.Word, start int) bool {
	if ctx.Cwd == "" {
		return false
	}
	for i := start; i < len(args); i++ {
		s, ok := check.LiteralString(args[i])
		if !ok {
			return false
		}
		if s == "--" {
			break
		}
		if strings.HasPrefix(s, "-") {
			continue
		}
		if filepath.IsAbs(s) && !check.IsPathUnder(s, ctx.Cwd) {
			return false
		}
	}
	return true
}

func init() { check.Register(goChecker{}, "go") }
