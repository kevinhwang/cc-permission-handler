package main

import (
	"fmt"
	"os"
	"strings"

	_ "cc-permission-handler/internal/checkers"
	"cc-permission-handler/internal/config"
	configpb "cc-permission-handler/internal/gen/config/v1"
	rulespb "cc-permission-handler/internal/gen/rules/v1"
	"cc-permission-handler/internal/prefer"
	"cc-permission-handler/internal/rules"
	"cc-permission-handler/internal/walker"

	"github.com/spf13/cobra"
)

func main() {
	if err := config.Load(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var (
		testMode bool
		cwd      string
	)

	root := &cobra.Command{
		Use:   "cc-permission-handler [flags] [command ...]",
		Short: "Claude Code PermissionRequest hook for auto-approving safe bash commands",
		Long: `A Claude Code PermissionRequest hook that auto-approves safe bash commands,
denies commands that should use native tools, and falls through to the
default permission prompt for everything else.

With no flags, runs as a hook (reads JSON from stdin, writes JSON to stdout).
With --test, evaluates the given commands and prints the result for each.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if testMode {
				if len(args) == 0 {
					return fmt.Errorf("--test requires at least one command argument")
				}
				runTest(cwd, args)
				return nil
			}
			runHook()
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.Flags().BoolVar(&testMode, "test", false, "test commands against the safety evaluation pipeline")
	root.Flags().StringVar(&cwd, "cwd", "", "working directory for path resolution (used with --test)")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runHook() {
	input, err := readInput(os.Stdin)
	if err != nil {
		return
	}
	if input.ToolName != "Bash" {
		return
	}

	command := strings.TrimSpace(input.ToolInput.Command)
	if command == "" {
		return
	}

	f, err := walker.ParseCommand(command)
	if err != nil {
		return
	}
	if len(f.Stmts) == 0 {
		return
	}

	// Layer 1: Prefer native tools (deny with suggestion).
	if config.PreferNativeTools(input.Cwd) && !prefer.HasSuppressPrefix(input.ToolInput.Description) {
		if msg, deny := prefer.CheckPreferBuiltin(f); deny {
			writeDeny(os.Stdout, msg)
			return
		}
	}

	// Layer 2: Safety evaluation (allow or fall through).
	ruleSet := resolveRules(input.Cwd)
	if walker.EvaluateAST(f, input.Cwd, nil, ruleSet) {
		writeAllow(os.Stdout)
	}
}

// resolveRules collects command rules from all matching projects for the
// given cwd. Projects are processed in config declaration order; for each
// command name, later projects override earlier ones.
func resolveRules(cwd string) *rulespb.RuleSet {
	var sets []*rulespb.RuleSet
	for _, proj := range config.MatchingProjects(cwd) {
		switch proj.CommandRules.(type) {
		case *configpb.Project_UseDefaultRules:
			defaultRS, err := rules.DefaultRules()
			if err != nil {
				continue
			}
			sets = append(sets, defaultRS)
		case *configpb.Project_CustomCommandRules:
			if ccr := proj.GetCustomCommandRules(); ccr != nil && ccr.RuleSet != nil {
				sets = append(sets, ccr.RuleSet)
			}
		}
	}
	if len(sets) == 0 {
		return nil
	}
	return rules.MergeRuleSets(sets...)
}

func runTest(cwd string, args []string) {
	const (
		green  = "\033[32m"
		yellow = "\033[33m"
		red    = "\033[31m"
		bold   = "\033[1m"
		dim    = "\033[2m"
		reset  = "\033[0m"
	)

	if cwd != "" {
		fmt.Fprintf(os.Stderr, "  %scwd=%s%s\n", dim, cwd, reset)
	}

	for _, cmd := range args {
		f, err := walker.ParseCommand(cmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %sFALL-THROUGH%s  %s%s%s (parse error)\n",
				yellow, reset, bold, cmd, reset)
			continue
		}

		if config.PreferNativeTools(cwd) {
			if msg, deny := prefer.CheckPreferBuiltin(f); deny {
				fmt.Fprintf(os.Stderr, "  %sDENY%s  %s%s%s\n         %s%s%s\n",
					red, reset, bold, cmd, reset, dim, msg, reset)
				continue
			}
		}

		result := walker.Evaluate(cmd, cwd, resolveRules(cwd))
		tag := yellow + "FALL-THROUGH" + reset
		if result {
			tag = green + "ALLOW" + reset
		}
		fmt.Fprintf(os.Stderr, "  %s  %s%s%s\n", tag, bold, cmd, reset)
	}
}
