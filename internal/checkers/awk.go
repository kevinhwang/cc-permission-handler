package checkers

import (
	"strings"

	"cc-permission-handler/internal/check"

	"mvdan.cc/sh/v3/syntax"
)

type awkChecker struct{}

func (awkChecker) Check(_ *check.Context, args []*syntax.Word) bool {
	i := 1
	for i < len(args) {
		s, ok := check.LiteralString(args[i])
		if !ok {
			return false
		}
		if s == "-f" || strings.HasPrefix(s, "--file") {
			return false
		}
		if s == "-F" || s == "-v" {
			i += 2
			continue
		}
		if s == "-e" || s == "--source" {
			if i+1 >= len(args) {
				return false
			}
			prog, ok := check.LiteralString(args[i+1])
			if !ok {
				return false
			}
			if awkProgramIsDangerous(prog) {
				return false
			}
			i += 2
			continue
		}
		if strings.HasPrefix(s, "-") {
			i++
			continue
		}
		if awkProgramIsDangerous(s) {
			return false
		}
		return true
	}
	return true
}

func awkProgramIsDangerous(prog string) bool {
	if strings.Contains(prog, "system") {
		return true
	}
	if strings.Contains(prog, "getline") {
		return true
	}
	// Detect output redirections: print/printf followed by > or |.
	// We look for ">" or "|" preceded by a non-operator context, which in
	// practice means after a print value or closing construct (not in a
	// comparison like "$3 > 100" where > follows a digit/space).
	//
	// The heuristic: flag ">>" always, and flag ">" or "|" when followed by
	// a quote, slash, or identifier-start (the redirect target), but NOT
	// when followed by "=" (>=) or same char (||), or preceded only by
	// regex context (/regex|alt/).
	if strings.Contains(prog, ">>") {
		return true
	}
	// Check for pipe-to-command: | followed by a quote or identifier
	for _, pat := range []string{`| "`, `|"`, `| '`, `|'`} {
		if strings.Contains(prog, pat) {
			return true
		}
	}
	// Check for output redirect: > followed by a quote, slash, or identifier.
	// This catches both literal targets and variable targets.
	n := len(prog)
	for i := 0; i < n; i++ {
		if prog[i] != '>' {
			continue
		}
		// Skip >= (comparison)
		if i+1 < n && prog[i+1] == '=' {
			continue
		}
		// Look at what follows > (skip optional space)
		j := i + 1
		for j < n && prog[j] == ' ' {
			j++
		}
		if j >= n {
			continue
		}
		// Redirect target: quoted string, path, or variable name
		next := prog[j]
		if next == '"' || next == '\'' || next == '/' || isAwkIdentStart(next) {
			return true
		}
	}
	return false
}

func isAwkIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func init() { check.Register(awkChecker{}, "awk", "gawk", "mawk", "nawk") }
