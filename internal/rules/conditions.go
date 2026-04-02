package rules

import (
	"slices"
	"strings"

	"cc-permission-handler/internal/check"
	"cc-permission-handler/internal/config"
	rulespb "cc-permission-handler/internal/gen/rules/v1"

	"mvdan.cc/sh/v3/syntax"
)

// EvalCtx provides the evaluation environment to condition evaluators.
type EvalCtx struct {
	Cwd       string
	WriteDirs []string

	IsPathAllowed func(path string) bool
	Evaluate      func(command, cwd string, writeDirs []string) bool

	// RuleSet is the resolved rule set, needed for ref_command_spec resolution.
	RuleSet *rulespb.RuleSet
}

// evalCondition evaluates a single condition against parsed args.
func evalCondition(cond *rulespb.Condition, parsed *parsedArgs, ctx *EvalCtx) bool {
	if cond == nil {
		return true
	}
	switch c := cond.Condition.(type) {
	case *rulespb.Condition_Always:
		return true

	case *rulespb.Condition_Not:
		return !evalCondition(c.Not.Condition, parsed, ctx)

	case *rulespb.Condition_NoArgs:
		return len(parsed.flags) == 0 && len(parsed.positionals) == 0

	case *rulespb.Condition_HasDoubleDash:
		return parsed.hasDoubleDash

	case *rulespb.Condition_HasFlagMatching:
		return evalHasFlagMatching(c.HasFlagMatching, parsed)

	case *rulespb.Condition_FlagArgCheck:
		return evalFlagArgCheck(c.FlagArgCheck, parsed, ctx)

	case *rulespb.Condition_EveryFlagMatches:
		return evalEveryFlagMatches(c.EveryFlagMatches, parsed)

	case *rulespb.Condition_EveryPositionalPasses:
		return evalEveryPositionalPasses(c.EveryPositionalPasses, parsed, ctx)

	case *rulespb.Condition_Subcommands:
		return evalSubcommandCheck(c.Subcommands, parsed, ctx)

	case *rulespb.Condition_MaxPositionals:
		return int32(len(parsed.positionals)) <= c.MaxPositionals.GetCount()

	default:
		return false
	}
}

func evalHasFlagMatching(hfm *rulespb.HasFlagMatching, parsed *parsedArgs) bool {
	switch m := hfm.Match.(type) {
	case *rulespb.HasFlagMatching_Exact:
		set := toSet(m.Exact.Flags)
		for _, f := range parsed.flags {
			if set[f.name] {
				return true
			}
			// Handle --flag=value tokens where the parser didn't split
			// (flag not in flagDefs). Check if the raw name starts with
			// an exact flag followed by '='.
			for _, exactFlag := range m.Exact.Flags {
				if strings.HasPrefix(f.name, exactFlag+"=") {
					return true
				}
			}
		}
		return false

	case *rulespb.HasFlagMatching_Pattern:
		return matchesPattern(m.Pattern, parsed)

	default:
		return false
	}
}

func matchesPattern(pf *rulespb.PatternFlags, parsed *parsedArgs) bool {
	for _, f := range parsed.flags {
		if matchesFlagPattern(pf, f.name) {
			return true
		}
	}
	return false
}

func matchesFlagPattern(pf *rulespb.PatternFlags, flagName string) bool {
	// Check short chars: -x (single char flag) matches if char is in short_chars.
	if pf.GetShortChars() != "" && len(flagName) == 2 && flagName[0] == '-' && flagName[1] != '-' {
		if strings.ContainsRune(pf.GetShortChars(), rune(flagName[1])) {
			return true
		}
	}
	// Check long prefixes.
	for _, prefix := range pf.LongPrefixes {
		if strings.HasPrefix(flagName, prefix) {
			return true
		}
	}
	return false
}

func evalFlagArgCheck(fac *rulespb.FlagArgCheck, parsed *parsedArgs, ctx *EvalCtx) bool {
	nameSet := toSet(fac.Names)
	for _, f := range parsed.flags {
		if !nameSet[f.name] {
			continue
		}
		// Flag is present — check its argument.
		if !evalCheck(fac.Check, f.value, parsed, ctx) {
			return false
		}
	}
	// Flag not present or all instances passed → vacuously true.
	return true
}

func evalEveryFlagMatches(efm *rulespb.EveryFlagMatches, parsed *parsedArgs) bool {
	noArgSet := toSet(efm.AllowedWithoutArgs)
	withArgSet := toSet(efm.AllowedWithArgs)
	for _, f := range parsed.flags {
		if noArgSet[f.name] || withArgSet[f.name] {
			continue
		}
		return false
	}
	return true
}

func evalEveryPositionalPasses(epp *rulespb.EveryPositionalPasses, parsed *parsedArgs, ctx *EvalCtx) bool {
	// SshRemoteEval is special: it consumes all positionals at once
	// (first = host, remaining = remote command). Evaluate it once with
	// the first positional rather than per-positional.
	if _, ok := epp.Check.GetCheck().(*rulespb.Check_SshRemoteEval); ok {
		if len(parsed.positionals) == 0 {
			return false
		}
		return evalSshRemoteEval(parsed.positionals[0], parsed, ctx)
	}
	for _, p := range parsed.positionals {
		if !evalCheck(epp.Check, p, parsed, ctx) {
			return false
		}
	}
	return true
}

func evalSubcommandCheck(sc *rulespb.SubcommandCheck, parsed *parsedArgs, ctx *EvalCtx) bool {
	if len(parsed.positionals) == 0 {
		return false
	}
	sub := parsed.positionals[0]

	// Check allowed_with_any_args.
	if slices.Contains(sc.AllowedWithAnyArgs, sub) {
		return true
	}

	// Check with_rules entries.
	for _, entry := range sc.WithRules {
		if !matchesEntry(entry, sub) {
			continue
		}
		// Found a matching entry — evaluate remaining args against its rules.
		// Extract raw words after the subcommand for re-parsing in ref specs.
		var remainingRawWords []*syntax.Word
		if len(parsed.positionalWordIndices) > 0 {
			subIdx := parsed.positionalWordIndices[0]
			if subIdx+1 < len(parsed.rawWords) {
				remainingRawWords = parsed.rawWords[subIdx+1:]
			}
		}
		remainingParsed := &parsedArgs{
			positionals: parsed.positionals[1:],
			rawWords:    remainingRawWords,
		}
		switch r := entry.Rules.(type) {
		case *rulespb.SubcommandEntry_CustomRules:
			return evaluateCustomRules(r.CustomRules, remainingParsed, ctx)
		case *rulespb.SubcommandEntry_RefCommandSpec:
			return evaluateRefCommandSpec(r.RefCommandSpec, remainingParsed, ctx)
		}
		return false
	}

	return false
}

func matchesEntry(entry *rulespb.SubcommandEntry, sub string) bool {
	return slices.Contains(entry.Names, sub)
}

func evaluateRefCommandSpec(refName string, parsed *parsedArgs, ctx *EvalCtx) bool {
	if ctx.RuleSet == nil {
		return false
	}
	spec := LookupCommand(ctx.RuleSet, refName)
	if spec == nil {
		return false
	}
	switch c := spec.Checker.(type) {
	case *rulespb.CommandSpec_CustomRules:
		// Re-parse the remaining args using the referenced spec's flag defs,
		// since the outer parser may not have known about the ref's flags.
		reparsed, ok := parseArgs(parsed.rawWords, collectFlagDefs(c.CustomRules), c.CustomRules.GetSupportCombinedShortFlags())
		if !ok {
			return false
		}
		return evaluateCustomRules(c.CustomRules, reparsed, ctx)
	default:
		return false
	}
}

func evalCheck(chk *rulespb.Check, target string, parsed *parsedArgs, ctx *EvalCtx) bool {
	if chk == nil {
		return true
	}
	switch chk.Check.(type) {
	case *rulespb.Check_WriteCheck:
		return ctx.IsPathAllowed(target)

	case *rulespb.Check_SshRemoteEval:
		return evalSshRemoteEval(target, parsed, ctx)

	case *rulespb.Check_RecurseEval:
		return evalRecurseEval(target, parsed, ctx)

	default:
		return false
	}
}

func evalSshRemoteEval(host string, parsed *parsedArgs, ctx *EvalCtx) bool {
	hostCfg, matched := config.MatchRemoteHost(host, ctx.Cwd)
	if !matched {
		return false
	}

	// Collect remaining positionals as the remote command.
	// The host was the first positional. Everything after it is the remote command.
	var remoteParts []string
	foundHost := false
	for _, p := range parsed.positionals {
		if !foundHost && p == host {
			foundHost = true
			continue
		}
		if foundHost {
			// Skip leading -- after host.
			if len(remoteParts) == 0 && p == "--" {
				continue
			}
			remoteParts = append(remoteParts, p)
		}
	}

	remoteCmd := strings.Join(remoteParts, " ")
	if remoteCmd == "" {
		return false
	}

	return ctx.Evaluate(remoteCmd, "", hostCfg.AllowWritePatterns)
}

func evalRecurseEval(_ string, parsed *parsedArgs, ctx *EvalCtx) bool {
	// Join all positionals from the first one onward.
	remaining, ok := check.LiteralArgs(parsed.rawWords)
	if !ok {
		return false
	}
	cmd := strings.Join(remaining, " ")
	if cmd == "" {
		return false
	}
	return ctx.Evaluate(cmd, ctx.Cwd, ctx.WriteDirs)
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
	}
	return m
}
