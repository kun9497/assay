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
		{Name: "bare", Version: "1.0-1"},
	}
	ResolveSourceVersions(pkgs)
	if got := pkgs[0].Source.Version; got != "2:1.0-1" {
		t.Errorf("Source.Version = %q, want the binary EVR 2:1.0-1 kept", got)
	}
	if pkgs[1].Source != nil {
		t.Errorf("a package with no Source was given one: %+v", pkgs[1].Source)
	}
}
