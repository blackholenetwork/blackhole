// Package version provides version information for the application
package version

import (
	"runtime"
)

var (
	// Version is the current version of the application
	version = "dev"

	// BuildTime is when the binary was built
	buildTime = "unknown"

	// GitCommit is the git commit hash
	gitCommit = "unknown"
)

// Info contains version information
type Info struct {
	Version   string `json:"version"`
	BuildTime string `json:"build_time"`
	GitCommit string `json:"git_commit"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Set updates the version information
func Set(v string) {
	if v != "" {
		version = v
	}
}

// SetBuildInfo updates build information
func SetBuildInfo(time, commit string) {
	if time != "" {
		buildTime = time
	}
	if commit != "" {
		gitCommit = commit
	}
}

// Get returns the current version
func Get() string {
	return version
}

// GetInfo returns complete version information
func GetInfo() Info {
	return Info{
		Version:   version,
		BuildTime: buildTime,
		GitCommit: gitCommit,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}
