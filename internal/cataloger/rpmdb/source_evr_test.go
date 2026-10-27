package rpmdb

import (
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// The branches the image test (scancmd's TestRun_A4_*) cannot reach: a
// SOURCERPM that does not parse keeps the binary's EVR rather than becoming
// empty or a bare epoch, and a package with no Source is left alone.
func TestResolveSourceVersions_UnparsableSourceRPMKeepsTheBinaryEVR(t *testing.T) {
	pkgs := []pkgmeta.Package{
		{Name: "odd", Version: "2:1.0-1", Upstream: "not-a-source-rpm", Source: &pkgmeta.SourcePackage{Name: "odd", Version: "2:1.0-1"}},
		{Name: "bare", Version: "1.0-1", Upstream: "bare-1.0-1.src.rpm"},
	}
	ResolveSourceVersions(pkgs)
	if got := pkgs[0].Source.Version; got != "2:1.0-1" {
		t.Errorf("Source.Version = %q, want the binary EVR 2:1.0-1 kept", got)
	}
	if pkgs[1].Source != nil {
		t.Errorf("a package with no Source was given one: %+v", pkgs[1].Source)
	}
}

// A tie between sibling epochs takes the lower: "" (no epoch) and "0" read
// as zero, so a tie between none and 2 is none. Unreachable from the image
// test's fixtures, which are all decided by a majority.
func TestMostCommonEpoch_TieTakesTheLower(t *testing.T) {
	if e, ok := mostCommonEpoch(map[string]int{"2": 1, "": 1}); !ok || e != "" {
		t.Errorf("tie between none and 2 = %q, %v; want none", e, ok)
	}
	if e, ok := mostCommonEpoch(map[string]int{"10": 2, "9": 2}); !ok || e != "9" {
		t.Errorf("tie between 9 and 10 = %q; want 9 (numeric, not lexical)", e)
	}
	if _, ok := mostCommonEpoch(nil); ok {
		t.Error("no siblings reported an epoch")
	}
}
