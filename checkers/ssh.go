package checkers

import (
	"strings"

	"cc-permission-handler/check"
	"cc-permission-handler/config"

	"mvdan.cc/sh/v3/syntax"
)

var sshSafeFlagsWithArg = check.ToSet("-b", "-c", "-D", "-i", "-l", "-L", "-m", "-p", "-R", "-w")
var sshSafeFlagsNoArg = check.ToSet(
	"-t", "-T", "-n", "-N", "-f", "-q", "-v", "-x", "-X", "-Y",
	"-A", "-a", "-C", "-g", "-K", "-k", "-4", "-6",
)

// sshChecker handles ssh commands by extracting the remote command and
// evaluating it recursively against the host's static configuration.
type sshChecker struct{}

func (sshChecker) Check(ctx *check.Context, args []*syntax.Word) bool {
	return checkRemoteSSH(ctx, args[1:])
}

// tshChecker handles Teleport's tsh client. Expects `tsh ssh [flags] host cmd...`.
type tshChecker struct{}

func (tshChecker) Check(ctx *check.Context, args []*syntax.Word) bool {
	if len(args) < 2 {
		return false
	}
	sub, ok := check.LiteralString(args[1])
	if !ok || sub != "ssh" {
		return false
	}
	return checkRemoteSSH(ctx, args[2:])
}

// checkRemoteSSH is the shared evaluation logic for ssh and tsh.
// sshArgs should start after the "ssh" command/subcommand (i.e. [flags... host [--] cmd...]).
func checkRemoteSSH(ctx *check.Context, sshArgs []*syntax.Word) bool {
	strArgs, ok := check.LiteralArgs(sshArgs)
	if !ok {
		return false
	}

	host, remoteCmd, ok := parseSSHArgs(strArgs)
	if !ok {
		return false
	}

	hostCfg, matched := config.MatchRemoteHost(host, ctx.Cwd)
	if !matched {
		return false
	}
	if remoteCmd == "" {
		return false
	}

	return ctx.Evaluate(remoteCmd, "", hostCfg.AllowWritePatterns)
}

// parseSSHArgs parses [flags..., host, [--], cmd...] and returns
// the destination host and the reconstructed remote command string.
func parseSSHArgs(args []string) (host, remoteCmd string, ok bool) {
	i := 0
	var dest string

	for i < len(args) {
		tok := args[i]

		if tok == "--" {
			i++
			if dest == "" && i < len(args) {
				dest = args[i]
				i++
			}
			break
		}

		if sshSafeFlagsWithArg[tok] {
			i += 2
			continue
		}
		if sshSafeFlagsNoArg[tok] {
			i++
			continue
		}

		// Combined short flags like -tt: every char must be safe.
		if strings.HasPrefix(tok, "-") && !strings.HasPrefix(tok, "--") && len(tok) > 2 {
			allSafe := true
			for _, ch := range tok[1:] {
				if !sshSafeFlagsNoArg["-"+string(ch)] {
					allSafe = false
					break
				}
			}
			if allSafe {
				i++
				continue
			}
			return "", "", false
		}

		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			return "", "", false
		}

		dest = tok
		i++
		if i < len(args) && args[i] == "--" {
			i++
		}
		break
	}

	if dest == "" || i >= len(args) {
		return dest, "", dest != ""
	}

	remaining := args[i:]
	if len(remaining) == 1 {
		return dest, remaining[0], true
	}
	return dest, strings.Join(remaining, " "), true
}

func init() {
	check.Register(sshChecker{}, "ssh")
	check.Register(tshChecker{}, "tsh")
}
