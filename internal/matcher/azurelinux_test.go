package matcher

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// TestMatch_AzureLinuxRPMComparerIsWired is the caller-first proof for D94's
// version.go clause: version.For("Azure Linux:3") must actually be reached
// through Match, not merely resolve in isolation -- the helper being right
// proves nothing if nothing calls it for THIS ecosystem (CLAUDE.md's own
// recurring-defect warning, and the exact shape amazon_test.go's own
// TestMatch_AmazonRPMComparerIsWired pins for D73). Deleting the "Azure
// Linux:" clause from version.go turns this into a coverage skip
// (SkipCoverage, "no version comparer") instead of a finding, and this is
// the only test that would notice.
//
// The same two package rows also carry D94's version-boundary proof: OSV's
// export strips both the epoch and the release's .azl3/.cm2 dist tag from
// every `fixed` bound (measured 2026-08-26: raw OVAL "0:1.42.0-7.azl3"
// becomes OSV "1.42.0-7"), so an installed, UNSTRIPPED "1.42.0-7.azl3" has
// to keep comparing correctly against the stripped "1.42.0-7" bound in BOTH
// directions:
//
//   - below the fix ("1.42.0-6.azl3") -- still vulnerable.
//   - AT the fix, dist tag and all ("1.42.0-7.azl3") -- rpmvercmp's own
//     trailing-segment rule (rpm_test.go's own "2.0.1a" > "2.0.1" row) makes
//     the dist-tagged release sort ABOVE the bare fixed release, so the fix
//     is correctly read as reached, not as still-vulnerable-by-string-length.
//
// Two rows for the SAME package name is deliberate, unlike amazon_test.go's
// own second row (a different, unrelated package name that produces no
// finding only because the store holds nothing for it, which proves nothing
// about whether the comparer ran at all): both grpc rows here are looked up
// against the ONE stored advisory, so the second row's absence from
// Findings can only mean the comparer genuinely ordered it above the fix.
func TestMatch_AzureLinuxRPMComparerIsWired(t *testing.T) {
	const eco = "Azure Linux:3"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00grpc": {{
				ID:       "AZL-2026-0001",
				Database: "AZL",
				Upstream: []string{"CVE-2026-61001"},
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "grpc",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "1.42.0-7"},
						},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "azurelinux", VersionID: "3.0"},
		Packages: []pkgmeta.Package{
			// Below the stripped fixed release -- rpmvercmp must actually run
			// for this to come out vulnerable rather than skipped.
			{Name: "grpc", Version: "1.42.0-6.azl3", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "grpc"}},
			// AT the fixed release, dist tag and all -- proves the trailing
			// dist tag does not make an already-fixed package look vulnerable.
			{Name: "grpc", Version: "1.42.0-7.azl3", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "grpc"}},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	for _, s := range res.Skipped {
		if s.Cause == SkipCoverage {
			t.Fatalf("grpc was skipped for coverage (%q) -- version.For(%q) is not wired", s.Reason, eco)
		}
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want exactly 1 (the below-fix row only): %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Package.Version != "1.42.0-6.azl3" {
		t.Errorf("finding is for version %q, want the below-fix row 1.42.0-6.azl3", f.Package.Version)
	}
	if f.Advisory.ID != "AZL-2026-0001" {
		t.Errorf("Advisory.ID = %q, want AZL-2026-0001", f.Advisory.ID)
	}
	var gotCVE bool
	for _, id := range f.Identifiers {
		if id == "CVE-2026-61001" {
			gotCVE = true
		}
	}
	if !gotCVE {
		t.Errorf("Identifiers = %v, want CVE-2026-61001 from Upstream (D3) -- Azure Linux "+
			"carries its CVE there, never in related", f.Identifiers)
	}
}

// TestMatch_AzureLinuxReleaseIsolation is D6's proof for Azure Linux
// specifically: an "Azure Linux:3" advisory must never judge an "Azure
// Linux:2" package, even when both carry the same package name and the
// cross-release comparison would (wrongly) report a finding. The store's
// Lookup is keyed on the exact ecosystem string (fakeStore.Lookup mirrors
// the real Bolt store's own key shape, ecosystem+"\x00"+name), so this also
// stands as a regression guard on that key never being loosened to a
// family-prefix match for a real ecosystem lookup the way familyMatches'
// OWN family-vs-archive comparison is allowed to be.
func TestMatch_AzureLinuxReleaseIsolation(t *testing.T) {
	const (
		eco2 = "Azure Linux:2"
		eco3 = "Azure Linux:3"
	)
	store := &fakeStore{
		covers: []string{eco2, eco3},
		byKey: map[string][]advisory.Advisory{
			// Only "Azure Linux:3" has an advisory for grpc.
			eco3 + "\x00grpc": {{
				ID:       "AZL-2026-0003",
				Database: "AZL",
				Upstream: []string{"CVE-2026-61003"},
				Affected: []advisory.Affected{{
					Ecosystem: eco3,
					Name:      "grpc",
					Ranges: []advisory.Range{{
						Type:   advisory.RangeEcosystem,
						Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.42.0-7"}},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Packages: []pkgmeta.Package{
			// Same name, same "vulnerable-looking" low version, but on
			// Azure Linux:2 -- which this store covers but holds NO grpc
			// advisory for. If the lookup ever crossed releases (matching
			// by family prefix instead of the exact key), this row would
			// wrongly report a finding against the Azure Linux:3 advisory.
			{Name: "grpc", Version: "1.10.0-1.cm2", Ecosystem: eco2,
				Source: &pkgmeta.SourcePackage{Name: "grpc"}},
			// The positive control, on the release that DOES have the
			// advisory -- proves the store fixture and comparer both work,
			// so the absence of a finding above is release isolation and
			// not a broken fixture.
			{Name: "grpc", Version: "1.30.0-1.azl3", Ecosystem: eco3,
				Source: &pkgmeta.SourcePackage{Name: "grpc"}},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want exactly 1 (Azure Linux:3 only): %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Package.Ecosystem != eco3 {
		t.Errorf("the one finding is on ecosystem %q, want %q -- an Azure Linux:2 package "+
			"was judged against an Azure Linux:3 advisory (D6 violation)", res.Findings[0].Package.Ecosystem, eco3)
	}
	// The Azure Linux:2 package must not even appear as a coverage skip --
	// its ecosystem IS covered, and a name lookup that simply found nothing
	// is an ordinary clean result, not an incomplete one.
	for _, s := range res.Skipped {
		if s.Package.Ecosystem == eco2 {
			t.Errorf("Azure Linux:2 grpc was skipped (%q); it should be silently clean, "+
				"not flagged incomplete", s.Reason)
		}
	}
}

// TestMatch_AzureLinuxBoundedIntroduced drives D94's measured 1.2%
// bounded-introduced shape ("1.18.0" rather than the "0" sentinel 98.8% of
// records carry) through Match, proving it is enforced as a real lower
// bound and not merely stored: a version below Introduced must NOT be
// treated as vulnerable, one inside [Introduced, Fixed) must, and one at or
// above Fixed must not.
func TestMatch_AzureLinuxBoundedIntroduced(t *testing.T) {
	const eco = "Azure Linux:3"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00golang": {{
				ID:       "AZL-2026-0002",
				Database: "AZL",
				Upstream: []string{"CVE-2026-61002"},
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "golang",
					Ranges: []advisory.Range{{
						Type:   advisory.RangeEcosystem,
						Events: []advisory.Event{{Introduced: "1.18.0"}, {Fixed: "1.19.0"}},
					}},
				}},
			}},
		},
	}
	for _, tc := range []struct {
		name, version string
		wantFinding   bool
	}{
		{"below the introduced bound", "1.17.5-1.azl3", false},
		{"inside the bounded range", "1.18.5-1.azl3", true},
		{"at the fixed bound", "1.19.0-1.azl3", false},
		{"above the fixed bound", "1.20.0-1.azl3", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := New(store).Match(pkgmeta.Target{
				Packages: []pkgmeta.Package{
					{Name: "golang", Version: tc.version, Ecosystem: eco,
						Source: &pkgmeta.SourcePackage{Name: "golang"}},
				},
			})
			if err != nil {
				t.Fatalf("Match: %v", err)
			}
			got := len(res.Findings) == 1
			if got != tc.wantFinding {
				t.Errorf("version %q: finding = %v, want %v (Findings: %+v)",
					tc.version, got, tc.wantFinding, res.Findings)
			}
		})
	}
}
