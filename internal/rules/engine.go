package rules

import (
	"cc-permission-handler/internal/check"
	rulespb "cc-permission-handler/internal/gen/rules/v1"

	"mvdan.cc/sh/v3/syntax"
)

// Evaluate checks whether a command invocation is safe according to the given
// CommandSpec. Returns true if the command is allowed.
func Evaluate(spec *rulespb.CommandSpec, ctx *EvalCtx, args []*syntax.Word) bool {
	switch c := spec.Checker.(type) {
	case *rulespb.CommandSpec_CustomRules:
		// Fast path: if the only rule is allow{always{}}, skip parsing.
		if isAlwaysAllow(c.CustomRules) {
			if c.CustomRules.GetRequireCwd() && ctx.Cwd == "" {
				return false
			}
			return true
		}
		parsed, ok := parseCommand(c.CustomRules, args)
		if !ok {
			return false
		}
		return evaluateCustomRules(c.CustomRules, parsed, ctx)

	case *rulespb.CommandSpec_SedChecker:
		if c, ok := check.Lookup("sed"); ok {
			checkCtx := &check.Context{
				Cwd:           ctx.Cwd,
				WriteDirs:     ctx.WriteDirs,
				IsPathAllowed: ctx.IsPathAllowed,
				Evaluate:      ctx.Evaluate,
			}
			return c.Check(checkCtx, args)
		}
		return false

	case *rulespb.CommandSpec_AwkChecker:
		if c, ok := check.Lookup("awk"); ok {
			checkCtx := &check.Context{
				Cwd:           ctx.Cwd,
				WriteDirs:     ctx.WriteDirs,
				IsPathAllowed: ctx.IsPathAllowed,
				Evaluate:      ctx.Evaluate,
			}
			return c.Check(checkCtx, args)
		}
		return false

	default:
		return false
	}
}

// evaluateCustomRules runs the allow/deny rule logic against parsed args.
func evaluateCustomRules(cr *rulespb.CustomRules, parsed *parsedArgs, ctx *EvalCtx) bool {
	if len(cr.GetRules()) == 0 {
		return false
	}
	if cr.GetRequireCwd() && ctx.Cwd == "" {
		return false
	}

	hasAllow := false
	for _, rule := range cr.GetRules() {
		switch r := rule.Action.(type) {
		case *rulespb.Rule_Allow:
			if !evalCondition(r.Allow.Condition, parsed, ctx) {
				return false
			}
			hasAllow = true
		case *rulespb.Rule_Deny:
			if evalCondition(r.Deny.Condition, parsed, ctx) {
				return false
			}
		case *rulespb.Rule_AlwaysAllow:
			hasAllow = true
		case *rulespb.Rule_AlwaysDeny:
			return false
		}
	}
	return hasAllow
}

// isAlwaysAllow returns true if the CustomRules consists of only a single
// allow { always {} } rule — meaning the command is safe with any args.
func isAlwaysAllow(cr *rulespb.CustomRules) bool {
	if len(cr.GetRules()) != 1 {
		return false
	}
	switch cr.GetRules()[0].Action.(type) {
	case *rulespb.Rule_AlwaysAllow:
		return true
	case *rulespb.Rule_Allow:
		r := cr.GetRules()[0].Action.(*rulespb.Rule_Allow)
		_, ok := r.Allow.GetCondition().GetCondition().(*rulespb.Condition_Always)
		return ok
	default:
		return false
	}
}

// parseCommand parses shell words into a parsedArgs using flag definitions
// extracted from the CustomRules conditions.
func parseCommand(cr *rulespb.CustomRules, args []*syntax.Word) (*parsedArgs, bool) {
	flagDefs := collectFlagDefs(cr)
	return parseArgs(args[1:], flagDefs, cr.GetSupportCombinedShortFlags())
}

// collectFlagDefs extracts flag definitions from all conditions in a CustomRules.
// This is needed so the parser knows which flags consume an argument.
func collectFlagDefs(cr *rulespb.CustomRules) map[string]flagDef {
	defs := make(map[string]flagDef)
	for _, rule := range cr.GetRules() {
		var cond *rulespb.Condition
		switch r := rule.Action.(type) {
		case *rulespb.Rule_Allow:
			cond = r.Allow.Condition
		case *rulespb.Rule_Deny:
			cond = r.Deny.Condition
		}
		collectFlagDefsFromCondition(cond, defs)
	}
	return defs
}

func collectFlagDefsFromCondition(cond *rulespb.Condition, defs map[string]flagDef) {
	if cond == nil {
		return
	}
	switch c := cond.Condition.(type) {
	case *rulespb.Condition_Not:
		collectFlagDefsFromCondition(c.Not.Condition, defs)

	case *rulespb.Condition_FlagArgCheck:
		for _, name := range c.FlagArgCheck.Names {
			defs[name] = flagDef{hasArg: c.FlagArgCheck.GetHasArg()}
		}

	case *rulespb.Condition_EveryFlagMatches:
		for _, name := range c.EveryFlagMatches.AllowedWithoutArgs {
			defs[name] = flagDef{hasArg: false}
		}
		for _, name := range c.EveryFlagMatches.AllowedWithArgs {
			defs[name] = flagDef{hasArg: true}
		}

	case *rulespb.Condition_Subcommands:
		// Recurse into subcommand overrides to collect their flag defs too.
		// This is needed for parsing the full command before subcommand dispatch.
		for _, entry := range c.Subcommands.WithRules {
			if cr := entry.GetCustomRules(); cr != nil {
				for _, rule := range cr.GetRules() {
					var sub *rulespb.Condition
					switch r := rule.Action.(type) {
					case *rulespb.Rule_Allow:
						sub = r.Allow.Condition
					case *rulespb.Rule_Deny:
						sub = r.Deny.Condition
					}
					collectFlagDefsFromCondition(sub, defs)
				}
			}
		}
	}
}
