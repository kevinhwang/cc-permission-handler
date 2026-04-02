package checkers

import (
	"strings"

	"cc-permission-handler/check"

	"mvdan.cc/sh/v3/syntax"
)

// findSafeNoArg are find primaries/operators that take no argument.
var findSafeNoArg = check.ToSet(
	"-print", "-print0", "-prune", "-depth", "-empty",
	"-daystart", "-xdev", "-mount", "-follow", "-noleaf",
	"-true", "-false",
	"-readable", "-writable", "-executable",
	"-not", "-and", "-or",
	// Parentheses used for grouping show up as literal args.
	"(", ")", "!",
)

// findSafeWithArg are find primaries that consume one following argument.
var findSafeWithArg = check.ToSet(
	"-name", "-iname", "-path", "-ipath",
	"-wholename", "-iwholename",
	"-type", "-xtype",
	"-maxdepth", "-mindepth",
	"-mtime", "-atime", "-ctime",
	"-mmin", "-amin", "-cmin",
	"-newer",
	"-size", "-perm",
	"-regex", "-iregex", "-regextype",
	"-user", "-group", "-uid", "-gid",
	"-samefile", "-links", "-inum",
	"-printf",
)

type findChecker struct{}

func (findChecker) Check(_ *check.Context, args []*syntax.Word) bool {
	for i := 1; i < len(args); i++ {
		s, ok := check.LiteralString(args[i])
		if !ok {
			return false
		}
		// Non-flag positional args (search paths) appear before primaries.
		if !strings.HasPrefix(s, "-") && s != "(" && s != ")" && s != "!" {
			continue
		}
		if findSafeNoArg[s] {
			continue
		}
		if findSafeWithArg[s] || strings.HasPrefix(s, "-newer") {
			i++ // skip the argument
			continue
		}
		return false
	}
	return true
}

// fdSafeNoArg are fd flags that take no argument.
var fdSafeNoArg = check.ToSet(
	"-H", "--hidden",
	"-I", "--no-ignore",
	"--no-ignore-vcs", "--no-ignore-parent",
	"-s", "--case-sensitive",
	"-i", "--ignore-case",
	"-g", "--glob",
	"-F", "--fixed-strings",
	"-a", "--absolute-path",
	"-l", "--list-details",
	"-L", "--follow",
	"-p", "--full-path",
	"-0", "--print0",
	"--strip-cwd-prefix",
	"-u", "--unrestricted",
	"--one-file-system",
	"--prune",
	"-q", "--quiet",
)

// fdSafeWithArg are fd flags that consume one following argument.
var fdSafeWithArg = check.ToSet(
	"-d", "--max-depth",
	"--min-depth",
	"-t", "--type",
	"-e", "--extension",
	"-E", "--exclude",
	"-c", "--color",
	"-j", "--threads",
	"-S", "--size",
	"--changed-within", "--changed-before",
	"--max-results",
	"--base-directory",
	"--path-separator",
	"--search-path",
)

type fdChecker struct{}

func (fdChecker) Check(_ *check.Context, args []*syntax.Word) bool {
	for i := 1; i < len(args); i++ {
		s, ok := check.LiteralString(args[i])
		if !ok {
			return false
		}
		if !strings.HasPrefix(s, "-") {
			continue // positional args (pattern, path)
		}
		if eqIdx := strings.Index(s, "="); eqIdx > 0 {
			flag := s[:eqIdx]
			if fdSafeWithArg[flag] || fdSafeNoArg[flag] {
				continue
			}
			return false
		}
		if fdSafeNoArg[s] {
			continue
		}
		if fdSafeWithArg[s] {
			i++ // skip the argument
			continue
		}
		return false
	}
	return true
}

func init() {
	check.Register(findChecker{}, "find")
	check.Register(fdChecker{}, "fd", "fdfind")
}
