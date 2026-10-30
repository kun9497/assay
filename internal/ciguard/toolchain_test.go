package ciguard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// QA 2026-10-30: v0.12.0 was built with go1.26.9, which carries GO-2026-6809,
// because setup-go's go-version "1.26" took whatever patch release the runner
// had and nothing held it to a floor. The floor is go.mod's toolchain line,
// raised when a stdlib advisory names a fix. Two things enforce it, and this
// test holds both in place rather than the number, which is go.mod's to
// carry: scripts/check-go-toolchain.sh runs in the release before GoReleaser
// and in CI's build job, and every GoReleaser build scans its own binary with
// scripts/release-vulncheck.sh before anything is published.
func TestRelease_QA1030_TheToolchainFloorAndTheBinaryScanAreWired(t *testing.T) {
	if !regexp.MustCompile(`(?m)^toolchain go1\.\d+\.\d+$`).MatchString(readRepoFile(t, "go.mod")) {
		t.Error("go.mod has no toolchain line: there is no floor for check-go-toolchain.sh to hold")
	}

	release := readRepoFile(t, ".github/workflows/release.yml")
	check := strings.Index(release, "run: sh scripts/check-go-toolchain.sh")
	gorel := strings.Index(release, "uses: goreleaser/goreleaser-action")
	switch {
	case check < 0:
		t.Error("release.yml does not run scripts/check-go-toolchain.sh")
	case gorel < 0:
		t.Error("release.yml has no GoReleaser step to hold the check before")
	case check > gorel:
		t.Error("release.yml checks the toolchain after GoReleaser has already built and published")
	}

	if !strings.Contains(readRepoFile(t, ".github/workflows/ci.yml"), "run: sh scripts/check-go-toolchain.sh") {
		t.Error("ci.yml does not run scripts/check-go-toolchain.sh")
	}

	// Every build, not the first: a second build id added later would ship
	// unscanned binaries.
	gr := readRepoFile(t, ".goreleaser.yaml")
	builds := strings.Count(gr, "\n  - id: ")
	hooks := strings.Count(gr, `cmd: sh scripts/release-vulncheck.sh "{{ .Path }}"`)
	if section := gr[strings.Index(gr, "\nbuilds:"):strings.Index(gr, "\narchives:")]; builds == 0 || strings.Count(section, "\n  - id: ") != hooks {
		t.Errorf(".goreleaser.yaml: %d build(s), %d release-vulncheck post hook(s); want one per build",
			strings.Count(section, "\n  - id: "), hooks)
	}
}
