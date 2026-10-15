// Package guardagent implements the Go telemetry agent for the Guard
// ecosystem. It buffers security events, metrics, and agent status locally
// and ships them to the Guard Core App ingestion API with at-least-once
// delivery guarantees: nothing acknowledged is lost, nothing
// unacknowledged is forgotten.
//
// The agent is a library, not a process: it never panics out of an exported
// method, never blocks the host beyond the documented overflow policy, and
// treats every telemetry failure as a log line plus a counter bump.
package guardagent

import (
	"runtime/debug"
	"strings"
)

// Version is the semantic version of the guard-agent-go module. It is
// reported to the ingestion API as agent_version and in the User-Agent
// header. Releases are published as v-prefixed git tags.
const Version = "3.2.4"

const guardCoreModule = "github.com/rennf93/guard-core-go/v4"

func guardCoreVersionFromBuildInfo(info *debug.BuildInfo) string {
	if info == nil {
		return ""
	}
	for _, dep := range info.Deps {
		if dep.Path != guardCoreModule {
			continue
		}
		if dep.Replace != nil && dep.Replace.Version != "" {
			return strings.TrimPrefix(dep.Replace.Version, "v")
		}
		return strings.TrimPrefix(dep.Version, "v")
	}
	return ""
}
