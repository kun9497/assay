package matcher

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// 2026-10-22 audit A13: when a record linked two groups, absorb() moved the
// absorbed group's winner -- Advisory, Evidence, MatchedName, severity -- onto
// the surviving finding, but not the disclosure fields that belong to that
// same record: CrossMappedFrom and MatchedViaProvides. The finding then named
// one record and described another's join (D10). The in-group swap (beats,
// in Match) has always carried them.
//
// The critical record sits in the group that gets absorbed, so it becomes the
// displayed record only through absorb.
func TestMatch_A13_AMergeCarriesTheDisplayedRecordsMirrorOrigin(t *testing.T) {
	mk := func(id, database, alias string) advisory.Advisory {
		a := advWithRange(id, "PyPI", "django", "0", "3.2.13", advisory.RangeEcosystem)
		a.Database, a.Aliases = database, []string{alias}
		return a
	}
	a := mk("GHSA-aaaa", "GHSA", "CVE-2022-0001")
	b := mk("PYSEC-2022-2", "PYSEC", "CVE-2022-0002")
	b.Severity = []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}}
	b.Affected[0].CrossMappedFrom = "MIRROR-ORIGIN-FIXTURE"
	c := mk("GO-2022-0003", "GO", "CVE-2022-0001")
	c.Aliases = []string{"CVE-2022-0001", "CVE-2022-0002"}

	s := fakeStore{byKey: map[string][]advisory.Advisory{key("PyPI", "django"): {a, b, c}}}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Advisory.ID != "PYSEC-2022-2" {
		t.Fatalf("displayed advisory = %s, want PYSEC-2022-2 (the absorbed group's critical winner)", f.Advisory.ID)
	}
	if f.CrossMappedFrom != "MIRROR-ORIGIN-FIXTURE" {
		t.Errorf("CrossMappedFrom = %q, want the displayed record's own MIRROR-ORIGIN-FIXTURE", f.CrossMappedFrom)
	}
}

// The same merge where the absorbed group's winner was reached through an apk
// provides clause (D95) and the surviving group's through the package's own
// name: MatchedName already followed the displayed record, MatchedViaProvides
// did not, so the finding named a provide and said it was not one.
func TestMatch_A13_AMergeCarriesTheDisplayedRecordsProvidesJoin(t *testing.T) {
	const eco = "Alpaquita:stream"
	own := advWithRange("BELL-A13-0001", eco, "liberica26-lite-jdk", "0", "99.0-r0", advisory.RangeEcosystem)
	own.Aliases = []string{"CVE-2026-7001"}
	viaProvide := advWithRange("BELL-A13-0002", eco, "openjdk26-lite-jdk", "0", "99.0-r0", advisory.RangeEcosystem)
	viaProvide.Aliases = []string{"CVE-2026-7002"}
	viaProvide.Severity = []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}}
	link := advWithRange("BELL-A13-0003", eco, "openjdk26-lite-jdk", "0", "99.0-r0", advisory.RangeEcosystem)
	link.Aliases = []string{"CVE-2026-7001", "CVE-2026-7002"}

	s := fakeStore{byKey: map[string][]advisory.Advisory{
		key(eco, "liberica26-lite-jdk"): {own},
		key(eco, "openjdk26-lite-jdk"):  {viaProvide, link},
	}}
	p := pkg("liberica26-lite-jdk", "26.0.1.0_p1-r0", eco)
	p.Source = &pkgmeta.SourcePackage{Name: "liberica26-lite"}
	p.Provides = []string{"openjdk26-lite-jdk"}

	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Advisory.ID != "BELL-A13-0002" || f.MatchedName != "openjdk26-lite-jdk" {
		t.Fatalf("displayed = %s via %s, want BELL-A13-0002 via openjdk26-lite-jdk", f.Advisory.ID, f.MatchedName)
	}
	if !f.MatchedViaProvides {
		t.Error("MatchedViaProvides = false, want true: the displayed record was reached through the provide")
	}
}
