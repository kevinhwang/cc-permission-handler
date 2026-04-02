package walker

import (
	"cc-permission-handler/internal/check"
	rulespb "cc-permission-handler/internal/gen/rules/v1"
	"cc-permission-handler/internal/rules"

	"mvdan.cc/sh/v3/syntax"
)

// shellKeywords are commands that execute arbitrary code and are always rejected.
var shellKeywords = check.ToSet("eval", "exec", "source", ".", "trap")

// walker walks a bash AST and determines whether every node is safe.
type walker struct {
	cwd       string
	writeDirs []string
	evalFunc  func(command, cwd string, writeDirs []string) bool
	ruleSet   *rulespb.RuleSet
}

func newWalker(cwd string, writeDirs []string, evalFunc func(string, string, []string) bool, ruleSet *rulespb.RuleSet) *walker {
	return &walker{cwd: cwd, writeDirs: writeDirs, evalFunc: evalFunc, ruleSet: ruleSet}
}

func (w *walker) stmtsAreSafe(stmts []*syntax.Stmt) bool {
	for _, stmt := range stmts {
		if !w.stmtIsSafe(stmt) {
			return false
		}
	}
	return true
}

func (w *walker) stmtIsSafe(stmt *syntax.Stmt) bool {
	if stmt.Background || stmt.Coprocess {
		return false
	}
	for _, redir := range stmt.Redirs {
		if !w.checkRedirect(redir) {
			return false
		}
	}
	if stmt.Cmd == nil {
		return len(stmt.Redirs) == 0
	}
	return w.commandIsSafe(stmt.Cmd)
}

func (w *walker) commandIsSafe(cmd syntax.Command) bool {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		return w.checkCall(c)
	case *syntax.BinaryCmd:
		return w.stmtIsSafe(c.X) && w.stmtIsSafe(c.Y)
	case *syntax.Subshell:
		return w.stmtsAreSafe(c.Stmts)
	case *syntax.Block:
		return w.stmtsAreSafe(c.Stmts)
	case *syntax.IfClause:
		return w.checkIfClause(c)
	case *syntax.WhileClause:
		return w.stmtsAreSafe(c.Cond) && w.stmtsAreSafe(c.Do)
	case *syntax.ForClause:
		return w.checkForClause(c)
	case *syntax.CaseClause:
		return w.checkCaseClause(c)
	case *syntax.TestClause:
		return w.testExprIsSafe(c.X)
	case *syntax.DeclClause:
		return w.checkDeclClause(c)
	case *syntax.ArithmCmd:
		return w.arithmExprIsSafe(c.X)
	case *syntax.TimeClause:
		if c.Stmt == nil {
			return true
		}
		return w.stmtIsSafe(c.Stmt)
	case *syntax.FuncDecl:
		return false
	case *syntax.CoprocClause:
		return false
	case *syntax.LetClause:
		for _, expr := range c.Exprs {
			if !w.arithmExprIsSafe(expr) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// checkCall checks whether a simple command (CallExpr) is safe by validating
// common invariants and dispatching to the registered Checker.
func (w *walker) checkCall(call *syntax.CallExpr) bool {
	for _, assign := range call.Assigns {
		// Reject PATH overrides — the command would resolve against
		// a modified PATH that we can't verify.
		if assign.Name != nil && assign.Name.Value == "PATH" {
			return false
		}
		if assign.Value != nil && !w.wordIsSafe(assign.Value) {
			return false
		}
		if assign.Array != nil {
			for _, elem := range assign.Array.Elems {
				if elem.Value != nil && !w.wordIsSafe(elem.Value) {
					return false
				}
			}
		}
	}

	if len(call.Args) == 0 {
		return true
	}

	name, ok := check.CommandName(call.Args[0])
	if !ok {
		return false
	}

	if shellKeywords[name] {
		return false
	}

	for _, arg := range call.Args[1:] {
		if !w.wordIsSafe(arg) {
			return false
		}
	}

	// Try rule-engine-based command spec first.
	if spec := rules.LookupCommand(w.ruleSet, name); spec != nil {
		ctx := &rules.EvalCtx{
			Cwd:           w.cwd,
			WriteDirs:     w.writeDirs,
			IsPathAllowed: w.isPathAllowed,
			Evaluate:      w.evalFunc,
			RuleSet:       w.ruleSet,
		}
		return rules.Evaluate(spec, ctx, call.Args)
	}

	// Fallback to legacy global checker registry (sed, awk builtins).
	if c, ok := check.Lookup(name); ok {
		ctx := &check.Context{
			Cwd:           w.cwd,
			WriteDirs:     w.writeDirs,
			IsPathAllowed: w.isPathAllowed,
			Evaluate:      w.evalFunc,
		}
		return c.Check(ctx, call.Args)
	}
	return false
}

func (w *walker) checkIfClause(ic *syntax.IfClause) bool {
	if !w.stmtsAreSafe(ic.Cond) || !w.stmtsAreSafe(ic.Then) {
		return false
	}
	if ic.Else != nil {
		return w.checkIfClause(ic.Else)
	}
	return true
}

func (w *walker) checkForClause(fc *syntax.ForClause) bool {
	switch loop := fc.Loop.(type) {
	case *syntax.WordIter:
		for _, item := range loop.Items {
			if !w.wordIsSafe(item) {
				return false
			}
		}
	case *syntax.CStyleLoop:
		if !w.arithmExprIsSafe(loop.Init) || !w.arithmExprIsSafe(loop.Cond) || !w.arithmExprIsSafe(loop.Post) {
			return false
		}
	default:
		return false
	}
	return w.stmtsAreSafe(fc.Do)
}

func (w *walker) checkCaseClause(cc *syntax.CaseClause) bool {
	if !w.wordIsSafe(cc.Word) {
		return false
	}
	for _, item := range cc.Items {
		for _, pattern := range item.Patterns {
			if !w.wordIsSafe(pattern) {
				return false
			}
		}
		if !w.stmtsAreSafe(item.Stmts) {
			return false
		}
	}
	return true
}

func (w *walker) checkDeclClause(dc *syntax.DeclClause) bool {
	for _, assign := range dc.Args {
		if assign.Value != nil && !w.wordIsSafe(assign.Value) {
			return false
		}
		if assign.Array != nil {
			for _, elem := range assign.Array.Elems {
				if elem.Value != nil && !w.wordIsSafe(elem.Value) {
					return false
				}
			}
		}
	}
	return true
}
