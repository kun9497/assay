package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// QA 2026-11-02 #2. An installed version no comparer can read was reported
// AFFECTED against every open-ended range -- the shape Debian's unfixed set,
// every CSAF no-fix entry and every [0, inf) OSV record use -- because the
// range walk resolved the "0" sentinel without ever passing v to the
// comparer. D9's rule is skipped-with-a-count, and dpkgdb emits Version ""
// for a stanza with no Version on exactly that promise. The open-range
// advisory must land in Skipped with the target's cause, like the fixed-range
// one beside it already did, and produce no Finding whose Evidence names a
// comparison nobody made.
func TestMatch_UnreadableInstalledVersionIsSkippedNotAffected(t *testing.T) {
	open := advisory.Advisory{
		ID:   "DEBIAN-OPEN-0001",
		Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{
			Ecosystem: "Debian:12",
			Name:      "zzpkg",
			Ranges:    []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}}},
		}},
	}
	fixed := advisory.Advisory{
		ID:   "DEBIAN-FIXED-0002",
		Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{
			Ecosystem: "Debian:12",
			Name:      "zzpkg",
			Ranges:    []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0-1"}}}},
		}},
	}
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Debian:12\x00zzpkg": {open, fixed}}}

	for _, v := range []string{"", "(none)", "not a version"} {
		t.Run("version "+strings.Trim(strings.ReplaceAll(v, " ", "_"), "()")+"", func(t *testing.T) {
			res, err := New(s).Match(pkgmeta.Target{
				Packages: []pkgmeta.Package{pkg("zzpkg", v, "Debian:12")},
			})
			if err != nil {
				t.Fatalf("Match error = %v, want nil", err)
			}
			if len(res.Findings) != 0 {
				t.Errorf("Findings = %+v, want none: version %q was never read, so nothing can be affected", res.Findings, v)
			}
			if len(res.Skipped) != 2 {
				t.Fatalf("Skipped = %d (%+v), want 2: both advisories are unevaluable against an unreadable version", len(res.Skipped), res.Skipped)
			}
			for _, sk := range res.Skipped {
				if sk.Cause != SkipTarget {
					t.Errorf("%s: Cause = %q, want %q: the installed version is the target's to fix", sk.AdvisoryID, sk.Cause, SkipTarget)
				}
				if !strings.Contains(sk.Reason, "could not be read") || !strings.Contains(sk.Reason, `"`+v+`"`) {
					t.Errorf("%s: Reason = %q, want it to say the installed version %q could not be read", sk.AdvisoryID, sk.Reason, v)
				}
			}
		})
	}
}

// The control: a readable version against the same two advisories is judged,
// so the check above is not refusing every version.
func TestMatch_ReadableVersionAgainstOpenAndFixedRangesIsJudged(t *testing.T) {
	open := advisory.Advisory{
		ID:   "DEBIAN-OPEN-0001",
		Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{
			Ecosystem: "Debian:12",
			Name:      "zzpkg",
			Ranges:    []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}}},
		}},
	}
	fixed := advisory.Advisory{
		ID:   "DEBIAN-FIXED-0002",
		Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{
			Ecosystem: "Debian:12",
			Name:      "zzpkg",
			Ranges:    []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0-1"}}}},
		}},
	}
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Debian:12\x00zzpkg": {open, fixed}}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("zzpkg", "1.0-2", "Debian:12")},
	})
	if err != nil {
		t.Fatalf("Match error = %v, want nil", err)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("Skipped = %+v, want none for a readable version", res.Skipped)
	}
	if len(res.Findings) != 1 || res.Findings[0].Advisory.ID != "DEBIAN-OPEN-0001" {
		t.Errorf("Findings = %+v, want exactly the open-ended advisory (1.0-2 clears the fix at 1.0-1)", res.Findings)
	}
}
