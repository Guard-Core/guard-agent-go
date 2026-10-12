package guardagent

import (
	"runtime/debug"
	"testing"
)

func TestGuardCoreVersionFromBuildInfo(t *testing.T) {
	dep := func(version string, replace *debug.Module) *debug.Module {
		return &debug.Module{Path: guardCoreModule, Version: version, Replace: replace}
	}
	cases := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{"nil build info", nil, ""},
		{"dependency absent", &debug.BuildInfo{Deps: []*debug.Module{{Path: "example.com/other", Version: "v1.0.0"}}}, ""},
		{"v prefix stripped", &debug.BuildInfo{Deps: []*debug.Module{dep("v4.3.3", nil)}}, "4.3.3"},
		{"replace version wins", &debug.BuildInfo{Deps: []*debug.Module{dep("v4.3.0", &debug.Module{Version: "v4.3.9"})}}, "4.3.9"},
		{"path replace without version falls back", &debug.BuildInfo{Deps: []*debug.Module{dep("v4.3.0", &debug.Module{Path: "../guard-core-go"})}}, "4.3.0"},
	}
	for _, tc := range cases {
		if got := guardCoreVersionFromBuildInfo(tc.info); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}
