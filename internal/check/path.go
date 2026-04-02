package check

import (
	"os"
	"path/filepath"
	"strings"
)

// RealPath resolves symlinks and cleans the path. For paths that don't
// fully exist (e.g., a new file being created), it resolves the longest
// existing prefix and appends the rest. This is critical on macOS where
// /tmp is a symlink to /private/tmp.
func RealPath(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved
	}
	cleaned := filepath.Clean(path)
	rest := ""
	cur := cleaned
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			if rest == "" {
				return resolved
			}
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		if rest == "" {
			rest = filepath.Base(cur)
		} else {
			rest = filepath.Join(filepath.Base(cur), rest)
		}
		cur = parent
	}
	return cleaned
}

// ExpandTilde expands ~ at the start of a path to the user's home directory.
// Returns the path unchanged if it doesn't start with ~ or if the home dir
// can't be determined.
func ExpandTilde(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		if path == "~" {
			return home
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

// IsPathUnder checks if path resolves to within dir.
func IsPathUnder(path, dir string) bool {
	resolved := RealPath(path)
	dirResolved := RealPath(dir)
	return resolved == dirResolved || strings.HasPrefix(resolved, dirResolved+string(os.PathSeparator))
}
