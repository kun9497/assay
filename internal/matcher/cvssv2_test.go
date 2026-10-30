package matcher

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/severity"
)

// D156 (audit A14): NVD rates every CVE from before 2016 it never re-scored
// with a CVSS v2 vector only -- 72,405 of 391,806 NVD ratings in the
// published database of 2026-10-27, none of them rated by any other source.
// The vector was stored (D13) but nothing scored v2, so the finding stayed
// unknown: counted as rated, banded as nothing. It is now scored from the v2
// base formula onto NVD's own v2 bands, used only when nothing else in that
// rating scores, and the rating says it came from v2 (D10).
func TestMatch_D156_AV2OnlyNVDRatingBandsTheFinding(t *testing.T) {
	a := advWithRange("DSA-D156-0001", "PyPI", "django", "0", "3.2.13", advisory.RangeEcosystem)
	a.Aliases = []string{"CVE-2014-0001"}
	s := fakeStore{
		byKey: map[string][]advisory.Advisory{key("PyPI", "django"): {a}},
		ratings: map[string][]advisory.Rating{"CVE-2014-0001": {{
			CVE: "CVE-2014-0001", Source: "NVD",
			Severity: []advisory.Severity{{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"}},
		}}},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != severity.High || f.Score != 7.5 {
		t.Errorf("finding = %v %.1f, want high 7.5 from NVD's v2 vector", f.Severity, f.Score)
	}
	var nvd *Rating
	for i := range f.Ratings {
		if f.Ratings[i].Database == "NVD" {
			nvd = &f.Ratings[i]
		}
	}
	if nvd == nil || nvd.Severity != severity.High || !nvd.FromCVSSv2 {
		t.Errorf("NVD rating = %+v, want high, marked as from CVSS v2", nvd)
	}
	for _, r := range f.Ratings {
		if r.Database != "NVD" && r.FromCVSSv2 {
			t.Errorf("rating %s is marked as from CVSS v2; only NVD's is", r.Database)
		}
	}
}

// v2 is a fallback, never a peer: a rating that carries a v3 vector too is
// banded by v3 alone, even where v2 scores it higher (2,272 published NVD
// ratings would move up under a plain max).
func TestMatch_D156_V3BeatsV2InTheSameRating(t *testing.T) {
	a := advWithRange("DSA-D156-0002", "PyPI", "django", "0", "3.2.13", advisory.RangeEcosystem)
	a.Aliases = []string{"CVE-2015-0002"}
	s := fakeStore{
		byKey: map[string][]advisory.Advisory{key("PyPI", "django"): {a}},
		ratings: map[string][]advisory.Rating{"CVE-2015-0002": {{
			CVE: "CVE-2015-0002", Source: "NVD",
			Severity: []advisory.Severity{
				{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
				{Type: "CVSS_V3", Score: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
			},
		}}},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[0]
	if f.Severity != severity.Low {
		t.Errorf("finding = %v %.1f, want low from the v3 vector alone", f.Severity, f.Score)
	}
	for _, r := range f.Ratings {
		if r.FromCVSSv2 {
			t.Errorf("rating %s is marked as from CVSS v2, but v3 banded it", r.Database)
		}
	}
}
