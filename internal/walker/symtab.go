package walker

import (
	"strings"

	"cc-permission-handler/internal/check"

	"mvdan.cc/sh/v3/syntax"
)

// symtab tracks literal variable assignments within a script so that
// simple variable expansions (e.g., $VAR, ${VAR}) can be resolved for
// rule evaluation. Only variables assigned with fully resolvable RHS
// values are tracked; anything else (command substitutions, external
// env, conditional assignments) causes the variable to be invalidated.
type symtab struct {
	vars map[string]string
}

func newSymtab() *symtab {
	return &symtab{vars: make(map[string]string)}
}

// set records a literal variable value. If the value is not resolvable,
// the variable is invalidated (removed).
func (s *symtab) set(name string, word *syntax.Word, resolve func(*syntax.Word) (string, bool)) {
	if word == nil {
		// `VAR=` (empty) is valid — empty string.
		s.vars[name] = ""
		return
	}
	if val, ok := resolve(word); ok {
		s.vars[name] = val
		return
	}
	// RHS is not resolvable — invalidate.
	delete(s.vars, name)
}

// get returns the literal value of a variable, if known.
func (s *symtab) get(name string) (string, bool) {
	v, ok := s.vars[name]
	return v, ok
}

// invalidate removes a variable from tracking.
func (s *symtab) invalidate(name string) {
	delete(s.vars, name)
}

// snapshot returns a shallow copy of the current variable state.
func (s *symtab) snapshot() map[string]string {
	snap := make(map[string]string, len(s.vars))
	for k, v := range s.vars {
		snap[k] = v
	}
	return snap
}

// restoreInvalidating restores a snapshot, but invalidates any variable
// that was modified or added since the snapshot was taken. This is used
// after conditional/loop scopes where we can't know which branch executed.
func (s *symtab) restoreInvalidating(snap map[string]string) {
	result := make(map[string]string, len(snap))
	for k, v := range snap {
		if cur, ok := s.vars[k]; ok && cur == v {
			result[k] = v
		}
		// Otherwise: var was changed or deleted inside scope — drop.
	}
	s.vars = result
}

// restoreExact restores a snapshot exactly, discarding all changes.
// Used for subshell scoping where changes don't propagate out.
func (s *symtab) restoreExact(snap map[string]string) {
	s.vars = snap
}

// resolveWord attempts to resolve a syntax.Word to a literal string,
// using the symtab to resolve simple parameter expansions ($VAR, ${VAR}).
// Falls back to check.LiteralString for words with no expansions.
func (s *symtab) resolveWord(word *syntax.Word) (string, bool) {
	if word == nil {
		return "", false
	}
	// Fast path: no expansions at all.
	if lit, ok := check.LiteralString(word); ok {
		return lit, true
	}
	// Attempt resolution via symtab.
	var b strings.Builder
	for _, part := range word.Parts {
		if !s.resolvePart(part, &b) {
			return "", false
		}
	}
	if b.Len() == 0 {
		return "", false
	}
	return b.String(), true
}

func (s *symtab) resolvePart(part syntax.WordPart, b *strings.Builder) bool {
	switch p := part.(type) {
	case *syntax.Lit:
		b.WriteString(p.Value)
		return true
	case *syntax.SglQuoted:
		b.WriteString(p.Value)
		return true
	case *syntax.DblQuoted:
		for _, dp := range p.Parts {
			if !s.resolvePart(dp, b) {
				return false
			}
		}
		return true
	case *syntax.ParamExp:
		if !isSimpleParamExp(p) {
			return false
		}
		val, ok := s.get(p.Param.Value)
		if !ok {
			return false
		}
		b.WriteString(val)
		return true
	default:
		return false
	}
}

// isSimpleParamExp returns true for plain $VAR or ${VAR} with no
// operators (no default, substitution, slicing, indirection, etc.).
func isSimpleParamExp(pe *syntax.ParamExp) bool {
	return pe.Param != nil &&
		pe.Exp == nil &&
		pe.Repl == nil &&
		pe.Slice == nil &&
		!pe.Length &&
		!pe.Excl &&
		!pe.Width &&
		pe.Names == 0
}
