package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// 2026-10-22 audit, A1. Canonical's 16.04, 18.04 and 20.04 FIPS builds spell
// the lineage `.fips.N`, not `+FipsN`: the live OSV record UBUNTU-CVE-2024-0727
// fixes openssl at 1.1.1f-1ubuntu2.fips.20 on Ubuntu:Pro:FIPS-updates:20.04,
// 1.1.1-1ubuntu2.fips.2.1~18.04.23.4 on 18.04 and 1.0.2g-1ubuntu4.fips.4.20.11
// on 16.04. The D53 detector matched only [~+]fips<digit>, so a 20.04 FIPS
// host was judged against mainline -- and dpkg sorts `fips` above the empty
// string, so 1.1.1f-1ubuntu2.fips.12 is "newer" than the mainline fix
// 1.1.1f-1ubuntu2.18: no finding, no skip, a clean report on a vulnerable
// host. The caller's test, through Match.
func TestMatch_UbuntuFIPSDotSpellingIsSkippedNotJudged(t *testing.T) {
	const eco = "Ubuntu:20.04:LTS"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00openssl": {{
				ID:       "UBUNTU-CVE-2026-0002",
				Database: "UBUNTU",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "openssl",
					Ranges: []advisory.Range{{
						Type:   advisory.RangeEcosystem,
						Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.1.1f-1ubuntu2.18"}},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "ubuntu", VersionID: "20.04", PrettyName: "Ubuntu 20.04.6 LTS"},
		Packages: []pkgmeta.Package{
			{Name: "libssl1.1", Version: "1.1.1f-1ubuntu2.fips.12", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "openssl"}},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d, want 0: a FIPS build is not judged against mainline", len(res.Findings))
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d, want 1 -- before the fix this was 0 findings AND 0 skips, a clean report: %+v",
			len(res.Skipped), res.Skipped)
	}
	if s := res.Skipped[0]; s.Cause != SkipCoverage || !strings.Contains(s.Reason, "FIPS") ||
		!strings.Contains(s.Reason, "1.1.1f-1ubuntu2.fips.12") {
		t.Errorf("skip = %+v, want a coverage skip naming FIPS and the installed version", s)
	}
}

// The detector rows: every spelling measured in the live record, and the
// adversarial negatives that keep the dot form from firing on an ordinary
// version.
func TestUbuntuLineageOf_FIPSDotSpelling(t *testing.T) {
	for _, tt := range []struct {
		version string
		want    string
	}{
		{"1.1.1f-1ubuntu2.fips.20", "FIPS"},
		{"1.1.1f-1ubuntu2.fips.2.8", "FIPS"},
		{"1.1.1-1ubuntu2.fips.2.1~18.04.23.4", "FIPS"},
		{"1.0.2g-1ubuntu4.fips.4.20.11", "FIPS"},
		{"1.0.2g-1ubuntu4.FIPS.4.6.1", "FIPS"},
		// The separator-less spelling, from the same dump.
		{"1.0.3-2fips3", "FIPS"},
		{"1.1.5-1fips1", "FIPS"},
		// Not a lineage: the dot form needs a dot on both sides and a digit.
		{"1.1.1f-1ubuntu2.fips", ""},
		{"1.1.1f-1ubuntu2.fipsy.2", ""},
		{"2.0-1ubuntu1.nofips.3", ""},
		{"1.0-1ubuntu1.fips-2", ""},
		// The trailing digit is required: without it a word segment such as
		// `.fips.beta` would mark an ordinary build as a lineage one.
		{"2.0-1ubuntu1.fips.beta", ""},
		// The separator-less form needs a digit on BOTH sides: a letter before
		// it, or no digit after, is an ordinary word, not a lineage.
		{"1.0-1ubuntunofips3", ""},
		{"2.0-1fipsy", ""},
	} {
		if got := ubuntuLineageOf(tt.version); got != tt.want {
			t.Errorf("ubuntuLineageOf(%q) = %q, want %q", tt.version, got, tt.want)
		}
	}
}
