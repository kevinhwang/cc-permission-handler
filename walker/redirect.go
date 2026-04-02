package walker

import (
	"path/filepath"
	"strings"

	"cc-permission-handler/check"
	"cc-permission-handler/config"

	"mvdan.cc/sh/v3/syntax"
)

var safeRedirectTargets = check.ToSet("/dev/null")

func (w *walker) checkRedirect(redir *syntax.Redirect) bool {
	switch redir.Op {
	case syntax.RdrIn:
		return true
	case syntax.DplOut, syntax.DplIn:
		return true
	case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		if redir.Hdoc != nil {
			return w.wordIsSafe(redir.Hdoc)
		}
		return true
	case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
		return w.isOutputRedirectSafe(redir)
	case syntax.RdrInOut:
		return false
	default:
		return false
	}
}

func (w *walker) isOutputRedirectSafe(redir *syntax.Redirect) bool {
	target, ok := check.LiteralString(redir.Word)
	if !ok {
		return false
	}
	return w.isPathAllowed(target)
}

// isPathAllowed checks if a path is writable. For local commands, it uses
// the project-scoped config. For remote commands (writeDirs is non-nil),
// it glob-matches against the remote host's allow_write_patterns.
func (w *walker) isPathAllowed(path string) bool {
	if safeRedirectTargets[path] {
		return true
	}
	if w.cwd == "" {
		return false
	}

	// Remote commands: glob-match against provided write patterns.
	// Don't expand ~ locally — remote paths are matched literally.
	if len(w.writeDirs) > 0 {
		return w.isRemotePathAllowed(path)
	}

	// Local commands: expand ~, resolve relative paths, check via config.
	// IsWriteAllowed handles symlink resolution internally.
	path = check.ExpandTilde(path)
	if !filepath.IsAbs(path) {
		path = filepath.Join(w.cwd, path)
	}
	return config.IsWriteAllowed(path, w.cwd)
}

// isRemotePathAllowed glob-matches a remote path against the remote host's
// allow_write_patterns. Relative paths (not starting with / or ~/) are
// resolved against the remote cwd if available.
func (w *walker) isRemotePathAllowed(path string) bool {
	if !filepath.IsAbs(path) && !strings.HasPrefix(path, "~/") {
		if w.cwd != "" {
			path = filepath.Join(w.cwd, path)
		} else {
			return false
		}
	}
	for _, pattern := range w.writeDirs {
		if config.GlobMatch(pattern, path) {
			return true
		}
	}
	return false
}
