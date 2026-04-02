// Package prefer implements the "prefer native tools" layer that steers
// Claude toward using Claude Code's built-in tools (Read, Grep, Glob, Edit)
// instead of bash equivalents (cat, grep, find, sed).
package prefer

import (
	"fmt"
	"strings"

	"cc-permission-handler/check"

	"mvdan.cc/sh/v3/syntax"
)

// SuppressPrefix is the escape hatch. If a Bash tool call's description
// contains this prefix, the prefer-builtin layer is skipped entirely.
const SuppressPrefix = "[SUPPRESS_PREFER_TOOL_WARNING]"

type preferredTool struct {
	tool    string
	message string
}

var preferredTools = map[string]preferredTool{
	"cat":   {"Read", "Use the Read tool to read files."},
	"head":  {"Read", "Use the Read tool with the `limit` parameter."},
	"tail":  {"Read", "Use the Read tool with `offset` and `limit` parameters."},
	"sed":   {"Edit", "Use the Edit tool for file modifications, or Read for viewing."},
	"awk":   {"Edit/Read/Grep", "Use the Edit, Read, or Grep tools instead."},
	"gawk":  {"Edit/Read/Grep", "Use the Edit, Read, or Grep tools instead."},
	"grep":  {"Grep", "Use the built-in Grep tool for content search."},
	"egrep": {"Grep", "Use the built-in Grep tool for content search."},
	"fgrep": {"Grep", "Use the built-in Grep tool for content search."},
	"rg":    {"Grep", "Use the built-in Grep tool for content search."},
	"find":  {"Glob", "Use the built-in Glob tool for file pattern matching."},
}

// CheckPreferBuiltin checks if the command is a simple invocation of a
// command that has a better native Claude Code tool equivalent.
func CheckPreferBuiltin(f *syntax.File) (string, bool) {
	call := extractSimpleCall(f)
	if call != nil {
		return checkSingleCall(call)
	}
	return checkPipeline(f)
}

func checkSingleCall(call *syntax.CallExpr) (string, bool) {
	if len(call.Args) == 0 {
		return "", false
	}

	name, ok := check.CommandName(call.Args[0])
	if !ok {
		return "", false
	}

	pref, ok := preferredTools[name]
	if !ok {
		return "", false
	}

	msg := fmt.Sprintf(
		"Do not use `%s` for this. %s "+
			"(If you must use Bash for this, add %s to the Bash tool's description.)",
		name, pref.message, SuppressPrefix,
	)
	return msg, true
}

const maxPipeStages = 3

// checkPipeline checks if the command is a simple pipeline where every
// stage is a preferred tool (e.g. cat file | head -10).
func checkPipeline(f *syntax.File) (string, bool) {
	calls := extractPipelineCalls(f)
	if len(calls) < 2 {
		return "", false
	}

	for _, call := range calls {
		if len(call.Args) == 0 {
			return "", false
		}
		name, ok := check.CommandName(call.Args[0])
		if !ok {
			return "", false
		}
		if _, ok := preferredTools[name]; !ok {
			return "", false
		}
	}

	// Use the last stage's preferred tool for the suggestion.
	lastName, _ := check.CommandName(calls[len(calls)-1].Args[0])
	pref := preferredTools[lastName]

	msg := fmt.Sprintf(
		"Do not use a pipeline for this. %s "+
			"(If you must use Bash for this, add %s to the Bash tool's description.)",
		pref.message, SuppressPrefix,
	)
	return msg, true
}

// extractPipelineCalls extracts CallExprs from a simple pipeline command.
// Returns nil if the command is not a pipeline, has non-call stages,
// or has more than maxPipeStages stages.
func extractPipelineCalls(f *syntax.File) []*syntax.CallExpr {
	if len(f.Stmts) != 1 {
		return nil
	}
	stmt := f.Stmts[0]
	if stmt.Background || stmt.Coprocess {
		return nil
	}
	return collectPipeCalls(stmt.Cmd)
}

func collectPipeCalls(cmd syntax.Command) []*syntax.CallExpr {
	switch c := cmd.(type) {
	case *syntax.BinaryCmd:
		if c.Op == syntax.Pipe {
			if c.Y.Background || c.Y.Coprocess {
				return nil
			}
			right, ok := c.Y.Cmd.(*syntax.CallExpr)
			if !ok {
				return nil
			}
			left := collectPipeCalls(c.X.Cmd)
			if left == nil {
				return nil
			}
			result := append(left, right)
			if len(result) > maxPipeStages {
				return nil
			}
			return result
		}
		// Unwrap cd && (pipeline) and (pipeline) || fallback.
		if c.Op == syntax.OrStmt {
			if c.X.Background || c.X.Coprocess {
				return nil
			}
			return collectPipeCalls(c.X.Cmd)
		}
		if c.Op == syntax.AndStmt && isCdCommand(c.X) {
			if c.Y.Background || c.Y.Coprocess {
				return nil
			}
			return collectPipeCalls(c.Y.Cmd)
		}
	case *syntax.CallExpr:
		return []*syntax.CallExpr{c}
	}
	return nil
}

func extractSimpleCall(f *syntax.File) *syntax.CallExpr {
	if len(f.Stmts) != 1 {
		return nil
	}
	stmt := f.Stmts[0]
	if stmt.Background || stmt.Coprocess {
		return nil
	}
	return extractCallFromCmd(stmt.Cmd)
}

func extractCallFromCmd(cmd syntax.Command) *syntax.CallExpr {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		return c
	case *syntax.BinaryCmd:
		if c.Op == syntax.OrStmt {
			if c.X.Background || c.X.Coprocess {
				return nil
			}
			return extractCallFromCmd(c.X.Cmd)
		}
		if c.Op == syntax.AndStmt && isCdCommand(c.X) {
			if c.Y.Background || c.Y.Coprocess {
				return nil
			}
			if call, ok := c.Y.Cmd.(*syntax.CallExpr); ok {
				return call
			}
		}
	}
	return nil
}

func isCdCommand(stmt *syntax.Stmt) bool {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	name, ok := check.CommandName(call.Args[0])
	return ok && name == "cd"
}

// HasSuppressPrefix checks if the description contains the suppress prefix.
func HasSuppressPrefix(description string) bool {
	return strings.Contains(description, SuppressPrefix)
}
