package checkers

import (
	"strings"

	"cc-permission-handler/internal/check"

	"mvdan.cc/sh/v3/syntax"
)

type sedChecker struct{}

func (sedChecker) Check(_ *check.Context, args []*syntax.Word) bool {
	if check.HasWriteFlags(args, "i", "--in-place") {
		return false
	}
	return checkSedProgram(args)
}

func checkSedProgram(args []*syntax.Word) bool {
	i := 1
	for i < len(args) {
		s, ok := check.LiteralString(args[i])
		if !ok {
			return false
		}
		if s == "-e" || s == "--expression" {
			if i+1 >= len(args) {
				return false
			}
			prog, ok := check.LiteralString(args[i+1])
			if !ok {
				return false
			}
			if !sedProgramIsSafe(prog) {
				return false
			}
			i += 2
			continue
		}
		if s == "-f" || s == "--file" {
			return false
		}
		if strings.HasPrefix(s, "-") {
			i++
			continue
		}
		// First non-flag, non-option argument is the program.
		return sedProgramIsSafe(s)
	}
	return true
}

// sedSafeSubstFlags are the allowed flags after s/pat/repl/FLAGS.
const sedSafeSubstFlags = "gpiI0123456789"

// sedProgramIsSafe checks that every command in the program is from
// a known-safe allowlist. Rejects unknown commands (including w, W, e).
func sedProgramIsSafe(prog string) bool {
	n := len(prog)
	i := 0
	for i < n {
		// Skip whitespace, semicolons, newlines, and closing braces between commands.
		for i < n && (prog[i] == ' ' || prog[i] == '\t' || prog[i] == ';' || prog[i] == '\n' || prog[i] == '}') {
			i++
		}
		if i >= n {
			break
		}

		// Skip address: /regex/ or number or $ or range.
		i = skipSedAddress(prog, i)
		if i >= n {
			break
		}
		// Optional comma + second address for ranges.
		if i < n && prog[i] == ',' {
			i++
			i = skipSedAddress(prog, i)
		}
		// Skip optional negation operator and whitespace before command.
		for i < n && (prog[i] == ' ' || prog[i] == '\t' || prog[i] == '!') {
			i++
		}
		if i >= n {
			break
		}

		ch := prog[i]

		// Opening brace starts a block — safe, the commands inside will be checked.
		if ch == '{' {
			i++
			continue
		}

		// s and y commands: parse delimited form, then check flags.
		if ch == 's' {
			i++
			if i >= n {
				return false
			}
			i = skipSedDelimited(prog, i, 2)
			if i < 0 {
				return false
			}
			// Check flags after the closing delimiter.
			for i < n && prog[i] != ';' && prog[i] != '\n' && prog[i] != '}' {
				if !strings.ContainsRune(sedSafeSubstFlags, rune(prog[i])) {
					return false
				}
				i++
			}
			continue
		}
		if ch == 'y' {
			i++
			if i >= n {
				return false
			}
			i = skipSedDelimited(prog, i, 2)
			if i < 0 {
				return false
			}
			continue
		}

		// b, t, T: branch/test commands — skip optional label name.
		if ch == 'b' || ch == 't' || ch == 'T' {
			i++
			// Skip optional whitespace then label.
			for i < n && prog[i] == ' ' {
				i++
			}
			for i < n && prog[i] != ';' && prog[i] != '\n' && prog[i] != '}' {
				i++
			}
			continue
		}

		// a, i, c: append/insert/change — skip the text argument.
		if ch == 'a' || ch == 'i' || ch == 'c' {
			i++
			if i < n && prog[i] == '\\' {
				i++
			}
			// Skip to end of line (the text).
			for i < n && prog[i] != '\n' {
				i++
			}
			continue
		}

		// r, R: read file into output — safe (reads, doesn't write).
		if ch == 'r' || ch == 'R' {
			i++
			for i < n && prog[i] != ';' && prog[i] != '\n' {
				i++
			}
			continue
		}

		// Safe single-character commands with no arguments.
		if strings.ContainsRune("dDpPnNqQlxhHgGz=", rune(ch)) {
			i++
			continue
		}

		// Label definition (:label).
		if ch == ':' {
			i++
			for i < n && prog[i] != ';' && prog[i] != '\n' && prog[i] != '}' {
				i++
			}
			continue
		}

		// Unrecognized command (including w, W, e) — deny.
		return false
	}
	return true
}

// skipSedAddress advances past an optional address at position i.
func skipSedAddress(prog string, i int) int {
	n := len(prog)
	if i >= n {
		return i
	}
	// /regex/ address
	if prog[i] == '/' || prog[i] == '\\' {
		delim := prog[i]
		if delim == '\\' {
			i++
			if i >= n {
				return i
			}
			delim = prog[i]
		}
		i++
		for i < n {
			if prog[i] == '\\' {
				i += 2
				continue
			}
			if prog[i] == delim {
				i++
				break
			}
			i++
		}
		return i
	}
	// $ address
	if prog[i] == '$' {
		return i + 1
	}
	// Numeric address
	if prog[i] >= '0' && prog[i] <= '9' {
		for i < n && prog[i] >= '0' && prog[i] <= '9' {
			i++
		}
		// Optional step: ~N
		if i < n && prog[i] == '~' {
			i++
			for i < n && prog[i] >= '0' && prog[i] <= '9' {
				i++
			}
		}
		return i
	}
	return i
}

// skipSedDelimited skips `count` delimited sections (e.g., 2 for s/pat/repl/).
// Returns the position after the closing delimiter, or -1 on error.
func skipSedDelimited(prog string, i int, count int) int {
	n := len(prog)
	if i >= n {
		return -1
	}
	delim := prog[i]
	i++
	seen := 0
	for i < n && seen < count {
		if prog[i] == '\\' {
			i += 2
			continue
		}
		if prog[i] == delim {
			seen++
		}
		i++
	}
	if seen < count {
		return -1
	}
	return i
}

func init() { check.Register(sedChecker{}, "sed", "gsed") }
