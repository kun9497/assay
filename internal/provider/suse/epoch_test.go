package suse

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// QA 2026-11-02 finding #5 (P3, the same shape as Red Hat's #4). purlRE
// read "pkg:rpm/suse/<name>@<version>" and stopped at the '?', so a purl's
// "epoch=N" qualifier never reached the stored fixed version while rpmdb
// writes the installed build "N:version-release". Today every one of the
// 10,031 epoch-qualified purls in the archive is a Liberty Linux build
// foldKey refuses, so the gap is latent -- one SLES package with an Epoch
// away from the P1. The fix is pkgmeta.EVROf's rule, shared with the scan
// side: a non-zero epoch qualifier is prefixed "epoch:" onto the version.
//
// The platform is a real SLES module; the package and epoch are synthetic
// (no folding key ships an epoch today), chosen so no fixture value is a
// substring of another.
const (
	epochPlat = "SUSE Linux Enterprise Module for Basesystem 15 SP6"
	epochPurl = "pkg:rpm/suse/pgbouncer@1.24.1-150600.3.1?arch=x86_64&epoch=1&upstream=pgbouncer-1.24.1-150600.3.1.src.rpm"
)

func epochDoc(t *testing.T) *document {
	t.Helper()
	return buildDoc(t, "CVE-2026-61107",
		[]string{epochPlat},
		map[string]string{"pgbouncer-1.24.1-150600.3.1": epochPurl},
		[]string{epochPlat + ":pgbouncer-1.24.1-150600.3.1"},
		nil, nil)
}

// The store-level statement: what convert writes for the fixed event, on
// the SLES key the module folds to.
func TestConvert_EpochQualifierReachesTheFixedVersion(t *testing.T) {
	var st stats
	adv, ok := convert(epochDoc(t), &st)
	if !ok {
		t.Fatal("convert dropped a document with one recommended build")
	}
	var fixed []string
	for _, a := range adv.Affected {
		if a.Ecosystem != "SLES:15.SP6" || a.Name != "pgbouncer" {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixed = append(fixed, e.Fixed)
				}
			}
		}
	}
	if len(fixed) != 1 || fixed[0] != "1:1.24.1-150600.3.1" {
		t.Errorf("fixed versions on SLES:15.SP6/pgbouncer = %q, want [%q] (the epoch=1 qualifier prefixed, as rpmdb spells the installed build)",
			fixed, "1:1.24.1-150600.3.1")
	}
	if st.RecommendedWithEpoch != 1 {
		t.Errorf("RecommendedWithEpoch = %d, want 1", st.RecommendedWithEpoch)
	}
	if st.RecommendedNamedByNEVRSplit != 0 || st.RecommendedEmptyVersionKept != 0 {
		t.Errorf("D131 counters moved (%d split, %d kept) on a purl that carries a version", st.RecommendedNamedByNEVRSplit, st.RecommendedEmptyVersionKept)
	}
}

// The scan-level statement through the real store and matcher: a build
// below the fix is told the fix, the build that carries it is clean.
func TestEpoch_InstalledBuildBelowTheFixIsAffected(t *testing.T) {
	var st stats
	adv, ok := convert(epochDoc(t), &st)
	if !ok {
		t.Fatal("convert dropped a document with one recommended build")
	}
	got := verdictsOf(t, adv,
		pkgmeta.Package{Name: "pgbouncer", Version: "1:1.24.1-150600.2.1", Ecosystem: "SLES:15.SP6"},
		pkgmeta.Package{Name: "pgbouncer", Version: "1:1.24.1-150600.3.1", Ecosystem: "SLES:15.SP6"})
	if v := got["SLES:15.SP6/pgbouncer@1:1.24.1-150600.2.1"]; v != "1:1.24.1-150600.3.1" {
		t.Errorf("pgbouncer 1:1.24.1-150600.2.1 on SLES 15 SP6 = %q, want the fix %q", v, "1:1.24.1-150600.3.1")
	}
	if v := got["SLES:15.SP6/pgbouncer@1:1.24.1-150600.3.1"]; v != "" {
		t.Errorf("pgbouncer 1:1.24.1-150600.3.1 on SLES 15 SP6 = %q, want clean: it is the build that carries the fix", v)
	}
}

// The counter reaches the progress line beside D131's, so the day SLES ships
// an epoch-carrying build on a folding key is visible in the nightly.
func TestStatsString_ReportsRecommendedWithEpoch(t *testing.T) {
	got := stats{RecommendedNamedByNEVRSplit: 5, RecommendedEmptyVersionKept: 2, SkippedLeapMirrorSplitBuild: 4, RecommendedWithEpoch: 9}.String()
	want := "5 recommended builds named by splitting their product id where the purl carried no version (D131, " +
		"2 such ids kept as spelt, 4 SLE entries not mirrored onto Leap because their only fix was such a build), " +
		"9 recommended builds carrying an epoch on a folding key"
	if !strings.Contains(got, want) {
		t.Errorf("stats.String() = %q, want it to contain %q", got, want)
	}
}
