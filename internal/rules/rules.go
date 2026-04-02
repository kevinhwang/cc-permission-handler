// Package rules provides a config-driven rule engine for evaluating command
// safety. Command specs are defined in textproto and evaluated against parsed
// shell arguments using composable conditions.
package rules

import (
	_ "embed"
	"fmt"
	"slices"
	"sync"

	rulespb "cc-permission-handler/internal/gen/rules/v1"

	"google.golang.org/protobuf/encoding/prototext"
)

//go:embed default.txtpb
var defaultRulesText []byte

var (
	defaultRules     *rulespb.RuleSet
	defaultRulesOnce sync.Once
	defaultRulesErr  error
)

// DefaultRules returns the compiled-in default rule set.
func DefaultRules() (*rulespb.RuleSet, error) {
	defaultRulesOnce.Do(func() {
		defaultRules = &rulespb.RuleSet{}
		defaultRulesErr = prototext.Unmarshal(defaultRulesText, defaultRules)
		if defaultRulesErr != nil {
			defaultRulesErr = fmt.Errorf("parsing default rules: %w", defaultRulesErr)
		}
	})
	return defaultRules, defaultRulesErr
}

// LookupCommand finds the CommandSpec for a given command name in a RuleSet.
func LookupCommand(ruleSet *rulespb.RuleSet, name string) *rulespb.CommandSpec {
	if ruleSet == nil {
		return nil
	}
	for _, cmd := range ruleSet.Commands {
		if slices.Contains(cmd.Names, name) {
			return cmd
		}
	}
	return nil
}

// MergeRuleSets merges multiple rule sets. For each command name, the last
// rule set wins (later entries override earlier ones).
func MergeRuleSets(sets ...*rulespb.RuleSet) *rulespb.RuleSet {
	seen := make(map[string]bool)
	var merged []*rulespb.CommandSpec

	// Process in reverse so later sets take priority.
	for i := len(sets) - 1; i >= 0; i-- {
		if sets[i] == nil {
			continue
		}
		for _, cmd := range sets[i].Commands {
			// Use the first name as the dedup key for each CommandSpec.
			key := ""
			skip := false
			for _, name := range cmd.Names {
				if seen[name] {
					skip = true
					break
				}
				if key == "" {
					key = name
				}
			}
			if skip {
				continue
			}
			for _, name := range cmd.Names {
				seen[name] = true
			}
			merged = append(merged, cmd)
		}
	}

	return &rulespb.RuleSet{Commands: merged}
}
