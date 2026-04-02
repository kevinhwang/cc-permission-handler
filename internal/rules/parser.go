package rules

import (
	"strings"

	"cc-permission-handler/internal/check"

	"mvdan.cc/sh/v3/syntax"
)

// flagDef describes a flag's argument behavior for parsing.
type flagDef struct {
	hasArg bool
}

// parsedArgs is the structured representation of a command's arguments.
type parsedArgs struct {
	flags       []parsedFlag
	positionals []string
	// rawWords stores the syntax.Word slice passed to parseArgs.
	rawWords []*syntax.Word
	// hasDoubleDash is true if -- was encountered.
	hasDoubleDash bool
	// positionalWordIndices maps positional index to the raw word index.
	positionalWordIndices []int
}

type parsedFlag struct {
	name  string // the flag name (e.g., "-o", "--output")
	value string // the flag's argument, if any
}

// resolveWordFunc is a function that resolves a syntax.Word to a literal
// string, potentially using a symtab. If nil, check.LiteralString is used.
type resolveWordFunc func(*syntax.Word) (string, bool)

func resolveWord(word *syntax.Word, resolve resolveWordFunc) (string, bool) {
	if resolve != nil {
		return resolve(word)
	}
	return check.LiteralString(word)
}

// parseArgs classifies shell words into flags and positionals.
// flagDefs maps flag names to their definitions (whether they take an arg).
// supportCombined enables -abc decomposition.
// resolve, if non-nil, is used to resolve words (with symtab support).
func parseArgs(words []*syntax.Word, flagDefs map[string]flagDef, supportCombined bool, resolve resolveWordFunc) (*parsedArgs, bool) {
	result := &parsedArgs{rawWords: words}
	pastDoubleDash := false

	for i := 0; i < len(words); i++ {
		s, ok := resolveWord(words[i], resolve)
		if !ok {
			return nil, false
		}

		if !pastDoubleDash && s == "--" {
			result.hasDoubleDash = true
			pastDoubleDash = true
			continue
		}

		if !pastDoubleDash && isFlag(s) {
			// Try --flag=value splitting.
			if eqIdx := strings.Index(s, "="); eqIdx > 0 && strings.HasPrefix(s, "--") {
				flagName := s[:eqIdx]
				flagVal := s[eqIdx+1:]
				if def, ok := flagDefs[flagName]; ok && def.hasArg {
					result.flags = append(result.flags, parsedFlag{name: flagName, value: flagVal})
					continue
				}
				// Unknown flag with =value — store as-is for EveryFlagMatches to reject.
				result.flags = append(result.flags, parsedFlag{name: s})
				continue
			}

			// Try combined short flags: -abc → -a, -b, -c
			if supportCombined && len(s) > 2 && s[0] == '-' && s[1] != '-' {
				if decomposed, ok := decomposeCombinedFlags(s, flagDefs, words, &i, resolve); ok {
					result.flags = append(result.flags, decomposed...)
					continue
				}
				// Decomposition failed (unknown char) — try as exact flag.
			}

			// Exact flag match.
			if def, ok := flagDefs[s]; ok && def.hasArg {
				var val string
				if i+1 < len(words) {
					i++
					val, ok = resolveWord(words[i], resolve)
					if !ok {
						return nil, false
					}
				}
				result.flags = append(result.flags, parsedFlag{name: s, value: val})
				continue
			}

			result.flags = append(result.flags, parsedFlag{name: s})
			continue
		}

		result.positionalWordIndices = append(result.positionalWordIndices, i)
		result.positionals = append(result.positionals, s)
	}

	return result, true
}

// decomposeCombinedFlags decomposes -abc into individual flag entries.
// Returns false if any char is unknown in flagDefs.
// If the last char has hasArg, it consumes the next word.
func decomposeCombinedFlags(s string, flagDefs map[string]flagDef, words []*syntax.Word, idx *int, resolve resolveWordFunc) ([]parsedFlag, bool) {
	chars := s[1:]
	var flags []parsedFlag

	for j, ch := range chars {
		name := "-" + string(ch)
		def, known := flagDefs[name]
		if !known {
			return nil, false
		}
		isLast := j == len([]rune(chars))-1
		if def.hasArg && !isLast {
			// Only the last char in a combined flag may consume an arg.
			return nil, false
		}
		if def.hasArg && isLast {
			var val string
			if *idx+1 < len(words) {
				*idx++
				var ok bool
				val, ok = resolveWord(words[*idx], resolve)
				if !ok {
					return nil, false
				}
			}
			flags = append(flags, parsedFlag{name: name, value: val})
		} else {
			flags = append(flags, parsedFlag{name: name})
		}
	}
	return flags, true
}

func isFlag(s string) bool {
	return len(s) > 1 && s[0] == '-'
}
