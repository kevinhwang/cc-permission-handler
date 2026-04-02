// Package config loads and provides access to the permission handler's
// textproto configuration file.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"cc-permission-handler/check"
	configpb "cc-permission-handler/gen/config/v1"

	"github.com/bmatcuk/doublestar/v4"
	"google.golang.org/protobuf/encoding/prototext"
)

const (
	envConfigPath  = "CC_PERMISSION_HANDLER_CONFIG"
	defaultRelPath = ".config/cc-permission-handler/config.txtpb"
)

var global = &configpb.Config{}

// Global returns the active configuration.
func Global() *configpb.Config { return global }

// SetGlobal replaces the global config (for tests).
func SetGlobal(c *configpb.Config) { global = c }

// Load reads the config file and sets the global config.
// If no config file exists, an empty config is used (most restrictive).
func Load() error {
	path := configPath()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			global = &configpb.Config{}
			return nil
		}
		return fmt.Errorf("reading config %s: %w", path, err)
	}

	var c configpb.Config
	if err := prototext.Unmarshal(data, &c); err != nil {
		return fmt.Errorf("parsing config %s: %w", path, err)
	}

	global = &c
	return nil
}

func configPath() string {
	if p := os.Getenv(envConfigPath); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return defaultRelPath
	}
	return filepath.Join(home, defaultRelPath)
}

// IsWriteAllowed checks if path is writable under any matching project
// for the given cwd.
func IsWriteAllowed(path, cwd string) bool {
	return isWriteAllowed(global, path, cwd)
}

func isWriteAllowed(c *configpb.Config, path, cwd string) bool {
	for _, proj := range matchingProjects(c, cwd) {
		if proj.GetAllowProjectWrite() {
			for _, pattern := range proj.PathPatterns {
				pattern = check.ExpandTilde(pattern)
				if matched, _ := doublestar.Match(pattern, path); matched {
					return true
				}
			}
		}
		for _, pattern := range proj.AllowWritePatterns {
			pattern = check.ExpandTilde(pattern)
			if matchResolved(pattern, path) {
				return true
			}
		}
	}
	return false
}

// MatchRemoteHost finds the first remote host entry matching host
// across all matching projects for the given cwd.
func MatchRemoteHost(host, cwd string) (*configpb.RemoteHost, bool) {
	return matchRemoteHost(global, host, cwd)
}

func matchRemoteHost(c *configpb.Config, host, cwd string) (*configpb.RemoteHost, bool) {
	for _, proj := range matchingProjects(c, cwd) {
		for _, rh := range proj.RemoteHosts {
			for _, pattern := range rh.HostPatterns {
				if matched, _ := doublestar.Match(pattern, host); matched {
					return rh, true
				}
			}
		}
	}
	return nil, false
}

func matchingProjects(c *configpb.Config, cwd string) []*configpb.Project {
	var result []*configpb.Project
	for _, proj := range c.Projects {
		for _, pattern := range proj.PathPatterns {
			pattern = check.ExpandTilde(pattern)
			if matchResolved(pattern, cwd) {
				result = append(result, proj)
				break
			}
		}
	}
	return result
}

// matchResolved tries glob matching against both the raw path and the
// symlink-resolved path. Handles cases like /tmp → /private/tmp on macOS.
func matchResolved(pattern, path string) bool {
	if matched, _ := doublestar.Match(pattern, path); matched {
		return true
	}
	resolved := check.RealPath(path)
	if resolved != path {
		if matched, _ := doublestar.Match(pattern, resolved); matched {
			return true
		}
	}
	return false
}

// GlobMatch is exported for use by the walker's remote path checking.
func GlobMatch(pattern, path string) bool {
	matched, _ := doublestar.Match(pattern, path)
	return matched
}
