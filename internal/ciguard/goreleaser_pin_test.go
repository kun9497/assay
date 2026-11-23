package ciguard

import (
	"regexp"
	"testing"
)

// The release job runs GoReleaser beside the signing key: a version range
// there lets a new binary in with no change to this repository (QA 2026-11-20).
func TestRelease_GoReleaserVersionIsExact(t *testing.T) {
	m := regexp.MustCompile(`(?m)goreleaser/goreleaser-action@[0-9a-f]{40}[^\n]*\n\s+with:\n\s+version: "([^"]*)"`).
		FindStringSubmatch(readRepoFile(t, ".github/workflows/release.yml"))
	if m == nil {
		t.Fatal("release.yml's GoReleaser step names no version")
	}
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(m[1]) {
		t.Errorf("GoReleaser version %q is not exact", m[1])
	}
}
