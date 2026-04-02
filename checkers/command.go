package checkers

import (
	"strings"

	"cc-permission-handler/check"

	"mvdan.cc/sh/v3/syntax"
)

type commandChecker struct{}

func (commandChecker) Check(ctx *check.Context, args []*syntax.Word) bool {
	i := 1
	for i < len(args) {
		s, ok := check.LiteralString(args[i])
		if !ok {
			return false
		}
		if s == "-v" || s == "-V" {
			return true
		}
		if s == "-p" {
			i++
			continue
		}
		if s == "--" {
			i++
			break
		}
		if strings.HasPrefix(s, "-") {
			return false
		}
		break
	}
	if i >= len(args) {
		return true
	}
	remaining, ok := check.LiteralArgs(args[i:])
	if !ok {
		return false
	}
	return ctx.Evaluate(strings.Join(remaining, " "), ctx.Cwd, ctx.WriteDirs)
}

func init() { check.Register(commandChecker{}, "command") }
