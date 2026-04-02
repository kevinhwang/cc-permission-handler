package checkers

import (
	"strings"

	"cc-permission-handler/check"

	"mvdan.cc/sh/v3/syntax"
)

type envChecker struct{}

func (envChecker) Check(ctx *check.Context, args []*syntax.Word) bool {
	i := 1
	for i < len(args) {
		s, ok := check.LiteralString(args[i])
		if !ok {
			return false
		}
		if s == "-S" || strings.HasPrefix(s, "--split-string") {
			return false
		}
		if s == "-u" || s == "--unset" || s == "-C" || s == "--chdir" {
			i += 2
			continue
		}
		if strings.HasPrefix(s, "--unset=") || strings.HasPrefix(s, "--chdir=") {
			i++
			continue
		}
		if strings.HasPrefix(s, "-") {
			i++
			continue
		}
		if strings.Contains(s, "=") && !strings.HasPrefix(s, "=") {
			i++
			continue
		}
		remaining, ok := check.LiteralArgs(args[i:])
		if !ok {
			return false
		}
		return ctx.Evaluate(strings.Join(remaining, " "), ctx.Cwd, ctx.WriteDirs)
	}
	return true
}

func init() { check.Register(envChecker{}, "env") }
