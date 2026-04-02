// Package check defines the shared contract between the walker (which
// dispatches commands) and the checkers (which evaluate them). Both sides
// depend on this package, breaking what would otherwise be a circular dependency.
package check

import "mvdan.cc/sh/v3/syntax"

// Context provides the evaluation environment to checkers, populated by
// the Walker at dispatch time. Function fields allow checkers to use Walker
// capabilities without importing the walker package.
type Context struct {
	Cwd       string
	WriteDirs []string

	// IsPathAllowed checks if a path resolves to within cwd or an allowed dir.
	IsPathAllowed func(path string) bool

	// Evaluate recursively evaluates a command string for safety.
	Evaluate func(command, cwd string, writeDirs []string) bool
}

// Checker evaluates whether a specific command invocation is safe.
// args includes the command name at args[0].
type Checker interface {
	Check(ctx *Context, args []*syntax.Word) bool
}
