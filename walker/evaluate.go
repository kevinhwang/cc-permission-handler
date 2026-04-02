// Package walker provides AST parsing and recursive safety evaluation
// of bash commands.
package walker

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Evaluate parses a bash command string and returns true only if every
// component is verifiably safe.
func Evaluate(command, cwd string) bool {
	return EvaluateWithDirs(command, cwd, nil)
}

// EvaluateWithDirs is like Evaluate but with explicit allowed write dirs
// (glob patterns). Used for remote command evaluation where write dirs
// come from the remote host config rather than the global config.
func EvaluateWithDirs(command, cwd string, writeDirs []string) bool {
	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}
	f, err := ParseCommand(command)
	if err != nil {
		return false
	}
	return EvaluateAST(f, cwd, writeDirs)
}

// EvaluateAST evaluates a pre-parsed command AST.
func EvaluateAST(f *syntax.File, cwd string, writeDirs []string) bool {
	if len(f.Stmts) == 0 {
		return false
	}
	w := newWalker(cwd, writeDirs, EvaluateWithDirs)
	return w.stmtsAreSafe(f.Stmts)
}

// ParseCommand parses a bash command string into an AST.
func ParseCommand(command string) (*syntax.File, error) {
	return syntax.NewParser(syntax.KeepComments(false)).Parse(
		strings.NewReader(command), "",
	)
}
