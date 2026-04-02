package checkers

import (
	"strings"

	"cc-permission-handler/check"

	"mvdan.cc/sh/v3/syntax"
)

// pathWritePathFlags are flags whose value is a path that must be write-allowed.
var pathWritePathFlags = check.ToSet("-t", "--target-directory")

// pathWriteSkipFlags are flags that consume an argument which is not a path.
var pathWriteSkipFlags = check.ToSet("-S", "--suffix", "--backup", "--sparse", "--reflink")

type pathWriteChecker struct{}

func (pathWriteChecker) Check(ctx *check.Context, args []*syntax.Word) bool {
	if ctx.Cwd == "" {
		return false
	}
	pastDashDash := false
	for i := 1; i < len(args); i++ {
		s, ok := check.LiteralString(args[i])
		if !ok {
			return false
		}
		if s == "--" {
			pastDashDash = true
			continue
		}
		if !pastDashDash && strings.HasPrefix(s, "-") {
			if eqIdx := strings.Index(s, "="); eqIdx > 0 {
				flag := s[:eqIdx]
				if pathWritePathFlags[flag] && !ctx.IsPathAllowed(s[eqIdx+1:]) {
					return false
				}
			} else if pathWritePathFlags[s] {
				i++
				if i >= len(args) {
					return false
				}
				val, ok := check.LiteralString(args[i])
				if !ok || !ctx.IsPathAllowed(val) {
					return false
				}
			} else if pathWriteSkipFlags[s] {
				i++ // skip the flag's argument
			}
			continue
		}
		if !ctx.IsPathAllowed(s) {
			return false
		}
	}
	return true
}

func init() { check.Register(pathWriteChecker{}, "cp", "mv", "rm", "mkdir", "touch", "tee") }
