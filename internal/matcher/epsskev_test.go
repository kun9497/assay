package matcher

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
)

// TestMatch_EPSSAndKEVAttachWithoutTouchingSeverity drives D86's core
// promise through Match: an exploit-probability annotation and a KEV
// membership attach as typed rating fields, expose through the accessors,
// and change NOTHING about the finding's severity — a probability is not a
// severity opinion, and the fixture's advisory is deliberately rated so any
// leakage into the band computation would move an assertable value.
func TestMatch_EPSSAndKEVAttachWithoutTouchingSeverity(t *testing.T) {
	const eco = "PyPI"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00leftpkg": {{
				ID:       "TEST-EK-0001",
				Database: "GHSA",
				Upstream: []string{"CVE-2099-1001"},
				Severity: []advisory.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "leftpkg",
					Ranges: []advisory.Range{{
						Type:   advisory.RangeEcosystem,
						Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}},
					}},
				}},
			}},
		},
		ratings: map[string][]advisory.Rating{
			"CVE-2099-1001": {{
				CVE:            "CVE-2099-1001",
				Source:         "EPSS",
				EPSS:           0.94432,
				EPSSPercentile: 0.99871,
				EPSSModel:      "v2026.06.15",
			}, {
				CVE:           "CVE-2099-1001",
				Source:        "KEV",
				KEV:           true,
				KEVDateAdded:  "2099-01-15",
				KEVRansomware: "Known",
			}},
		},
	}
	target := pkgmeta.Target{
		Packages: []pkgmeta.Package{{Name: "leftpkg", Version: "1.0.0", Ecosystem: eco}},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]

	// The band is the record's own, untouched by the two opinionless rows.
	if f.Severity != severity.Critical {
		t.Errorf("Severity = %v, want critical — an EPSS/KEV row must not move the band", f.Severity)
	}

	kev, ok := f.KnownExploited()
	if !ok {
		t.Fatalf("KnownExploited() found nothing; Ratings = %+v", f.Ratings)
	}
	if kev.KEVDateAdded != "2099-01-15" || kev.KEVRansomware != "Known" {
		t.Errorf("KEV rating = %+v, want dateAdded 2099-01-15 and ransomware Known", kev)
	}
	p, ok := f.MaxEPSS()
	if !ok || p != 0.94432 {
		t.Errorf("MaxEPSS() = %v, %v; want 0.94432, true", p, ok)
	}
	for _, r := range f.Ratings {
		if (r.Database == "EPSS" || r.Database == "KEV") && !r.NoSeverityOpinion {
			t.Errorf("%s rating must be marked NoSeverityOpinion — it carried no vectors", r.Database)
		}
	}
	// EPSSPercentile is a SEPARATE FIRST.org number from EPSS itself (a
	// probability vs. where that probability ranks against every other
	// scored CVE) — the store's own ingestion test guards against the two
	// columns swapping on the way in, and this is the matching guard on the
	// way out: annotate() must copy r.EPSSPercentile, not r.EPSS again, into
	// the rating it attaches. The fixture's two values (0.94432 vs 0.99871)
	// are chosen not to collide, so a copy-paste of the wrong field is
	// visible here even though nothing before this line ever read the field.
	var epss Rating
	for _, r := range f.Ratings {
		if r.Database == "EPSS" {
			epss = r
		}
	}
	if epss.EPSSPercentile != 0.99871 {
		t.Errorf("EPSS rating's EPSSPercentile = %v, want 0.99871 — the probability must not "+
			"be published as the percentile", epss.EPSSPercentile)
	}
}

// TestMatch_NoEPSSMeansAbsentNotZero holds D17's shape on the new accessor:
// a finding with no EPSS row answers (0, false), never (0, true) — zero is
// the SAFEST possible probability and coercing absent to it would be the
// exact inversion of what absent means.
func TestMatch_NoEPSSMeansAbsentNotZero(t *testing.T) {
	const eco = "PyPI"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00leftpkg": {{
				ID:       "TEST-EK-0002",
				Database: "GHSA",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "leftpkg",
					Ranges: []advisory.Range{{
						Type:   advisory.RangeEcosystem,
						Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Packages: []pkgmeta.Package{{Name: "leftpkg", Version: "1.0.0", Ecosystem: eco}},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	if p, ok := res.Findings[0].MaxEPSS(); ok || p != 0 {
		t.Errorf("MaxEPSS() = %v, %v; want 0, false — absent must stay absent", p, ok)
	}
	if _, ok := res.Findings[0].KnownExploited(); ok {
		t.Error("KnownExploited() = true on a finding with no KEV row")
	}
}
