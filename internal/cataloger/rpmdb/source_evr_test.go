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

// src builds a package from its fields, with the Source toPackage gives it.
func src(name, version, srpm, eco string) pkgmeta.Package {
	return pkgmeta.Package{Name: name, Version: version, Upstream: srpm, Ecosystem: eco,
		Source: &pkgmeta.SourcePackage{Name: pkgmeta.SourceRPMName(srpm), Version: version}}
}

func sourceVersions(t *testing.T, pkgs []pkgmeta.Package) map[string]string {
	t.Helper()
	ResolveSourceVersions(pkgs)
	out := map[string]string{}
	for _, p := range pkgs {
		out[p.Name] = p.Source.Version
	}
	return out
}

// Each step of the epoch order, held where the steps disagree (the image
// test's fixtures agree on every step, so they could not tell one from the
// next; branch review wf_8d3f5559-cf7).
func TestResolveSourceVersions_EpochOrder(t *testing.T) {
	const eco = "Red Hat:9"
	t.Run("the main package from the same SRPM outranks the vote", func(t *testing.T) {
		got := sourceVersions(t, []pkgmeta.Package{
			src("foo", "2:1.0-1", "foo-1.0-1.src.rpm", eco),
			src("foo-a", "1.0-1", "foo-1.0-1.src.rpm", eco),
			src("foo-b", "1.0-1", "foo-1.0-1.src.rpm", eco),
			src("foo-x", "0.5-1", "foo-1.0-1.src.rpm", eco),
		})
		if got["foo-x"] != "2:1.0-1" {
			t.Errorf("foo-x source = %q, want 2:1.0-1 from the main package, not the siblings' 0", got["foo-x"])
		}
	})
	t.Run("a main package from another SRPM does not outrank the vote", func(t *testing.T) {
		// A partial update across an Epoch bump: foo is still the old build.
		got := sourceVersions(t, []pkgmeta.Package{
			src("foo", "1:1.0-2", "foo-1.0-2.src.rpm", eco),
			src("foo-libs", "1.1-1", "foo-1.1-1.src.rpm", eco),
			src("foo-devel", "1.1-1", "foo-1.1-1.src.rpm", eco),
		})
		if got["foo-libs"] != "1.1-1" {
			t.Errorf("foo-libs source = %q, want 1.1-1 from its own build's siblings", got["foo-libs"])
		}
	})
	t.Run("with no vote, a main package from another SRPM is next", func(t *testing.T) {
		got := sourceVersions(t, []pkgmeta.Package{
			src("bar", "3:1.0-1", "bar-1.0-1.src.rpm", eco),
			src("bar-sub", "2.0-1", "bar-1.0-2.src.rpm", eco),
		})
		if got["bar-sub"] != "3:1.0-2" {
			t.Errorf("bar-sub source = %q, want 3:1.0-2", got["bar-sub"])
		}
	})
	t.Run("with nothing else, the binary's own epoch", func(t *testing.T) {
		got := sourceVersions(t, []pkgmeta.Package{
			src("npm", "1:8.19.3-1.16.19.1.1.el9_2", "nodejs-16.19.1-1.el9_2.src.rpm", eco),
		})
		if got["npm"] != "1:16.19.1-1.el9_2" {
			t.Errorf("npm source = %q, want 1:16.19.1-1.el9_2", got["npm"])
		}
	})
	t.Run("the vote takes the most common epoch, not the lowest", func(t *testing.T) {
		// ubi9/perl-532's shape without perl itself: at the SRPM's
		// version-release, perl-interpreter, perl-libs (4) outnumber perl-doc (0).
		got := sourceVersions(t, []pkgmeta.Package{
			src("perl-interpreter", "4:5.32.1-484.el9_8", "perl-5.32.1-484.el9_8.src.rpm", eco),
			src("perl-libs", "4:5.32.1-484.el9_8", "perl-5.32.1-484.el9_8.src.rpm", eco),
			src("perl-doc", "5.32.1-484.el9_8", "perl-5.32.1-484.el9_8.src.rpm", eco),
			src("perl-B", "1.80-484.el9_8", "perl-5.32.1-484.el9_8.src.rpm", eco),
		})
		if got["perl-B"] != "4:5.32.1-484.el9_8" {
			t.Errorf("perl-B source = %q, want 4:5.32.1-484.el9_8", got["perl-B"])
		}
	})
}

// Azure Linux (CBL-Mariner included) and Photon write no usable epoch in
// their fixed versions -- Azure always 0:, Photon none -- so an epoch on the
// source side sorts above every fix. Their source version carries none:
// perl's 4 must not reach perl-Errno, and perl itself, whose lookup is the
// same one, compares 5.38.2-507 against 0:5.38.2-509 (branch review
// wf_8d3f5559-cf7: A4 had spread perl's epoch to every subpackage there).
// Every release of each family is listed, so a prefix narrowed to one
// release fails here (review wf_d60bfbd2-23b).
func TestResolveSourceVersions_EpochlessFeedsGetNoEpoch(t *testing.T) {
	for _, eco := range []string{"Azure Linux:3", "Azure Linux:2", "Photon OS:5", "Photon OS:4", "Photon OS:3"} {
		got := sourceVersions(t, []pkgmeta.Package{
			src("perl", "4:5.38.2-507.azl3", "perl-5.38.2-507.azl3.src.rpm", eco),
			src("perl-Errno", "1.37-507.azl3", "perl-5.38.2-507.azl3.src.rpm", eco),
		})
		if got["perl"] != "5.38.2-507.azl3" || got["perl-Errno"] != "5.38.2-507.azl3" {
			t.Errorf("%s: sources = %v, want 5.38.2-507.azl3 for both", eco, got)
		}
	}
}
