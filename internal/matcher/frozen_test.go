package matcher

import (
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
)

// D110 at the matcher: FrozenSince comes from Meta.Providers[*].Frozen, keyed
// by the matched entry's ecosystem, and is set at both places Finding is
// populated -- the append and the D25 winner swap -- exactly where D108's
// CrossMappedFrom is.

var d110Since = time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)

func frozenMeta() store.Meta {
	return store.Meta{Providers: map[string]store.Provenance{
		"osv": {
			Ecosystems: []string{"Debian:11", "Debian:12"},
			Frozen:     map[string]time.Time{"Debian:11": d110Since},
		},
	}}
}

// The append site, with a live key in the same Match so a lookup that ignored
// the key (every finding frozen) is caught as surely as one that never ran.
func TestMatch_FrozenSince_SetFromMetaOnTheFrozenKeyOnly(t *testing.T) {
	calls := 0
	s := fakeStore{
		byKey: map[string][]advisory.Advisory{
			"Debian:11\x00curl": {advWithRange("DEBIAN-A", "Debian:11", "curl", "0", "8.0.0", advisory.RangeEcosystem)},
			"Debian:12\x00curl": {advWithRange("DEBIAN-B", "Debian:12", "curl", "0", "8.0.0", advisory.RangeEcosystem)},
			"Debian:11\x00zlib": {advWithRange("DEBIAN-C", "Debian:11", "zlib", "0", "2.0.0", advisory.RangeEcosystem)},
		},
		meta:      frozenMeta(),
		metaCalls: &calls,
	}
	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{
		pkg("curl", "7.0.0", "Debian:11"),
		pkg("curl", "7.0.0", "Debian:12"),
		pkg("zlib", "1.0.0", "Debian:11"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]time.Time{}
	for _, f := range res.Findings {
		got[f.Advisory.ID] = f.FrozenSince
	}
	if len(got) != 3 {
		t.Fatalf("findings = %v, want DEBIAN-A, DEBIAN-B, DEBIAN-C", got)
	}
	for _, id := range []string{"DEBIAN-A", "DEBIAN-C"} {
		if !got[id].Equal(d110Since) {
			t.Errorf("%s FrozenSince = %v, want %v (Debian:11 is frozen)", id, got[id], d110Since)
		}
	}
	if !got["DEBIAN-B"].IsZero() {
		t.Errorf("DEBIAN-B FrozenSince = %v, want zero (Debian:12 is live)", got["DEBIAN-B"])
	}
	// Meta is one record: read once per Match, not once per finding or
	// package. Covers is the fake's own method and does not count here.
	if calls != 1 {
		t.Errorf("Meta read %d times in one Match, want 1", calls)
	}
}

// The winner-swap site. An unrated record is appended first and a rated one
// on the same CVE then beats it (D25), so the finding's displayed record is
// set by the swap branch. Because a finding groups one package's records and
// every matched entry's ecosystem is the package's, dropping the swap's
// FrozenSince assignment leaves the append site's (identical) value in place:
// that mutation is an equivalent, documented at the assignment. What this
// test holds is that the swap does not CLEAR it -- a swap that reset the
// field, or copied it from anything but the frozen map, goes red here.
func TestMatch_FrozenSince_SurvivesTheWinnerSwap(t *testing.T) {
	unrated := advWithRange("OTHER-CVE-2026-1", "Debian:11", "curl", "0", "8.0.0", advisory.RangeEcosystem)
	unrated.Aliases = []string{"CVE-2026-1"}
	rated := advWithRange("DEBIAN-CVE-2026-1", "Debian:11", "curl", "0", "8.0.0", advisory.RangeEcosystem)
	rated.Aliases = []string{"CVE-2026-1"}
	rated.Severity = []advisory.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
	s := fakeStore{
		byKey: map[string][]advisory.Advisory{"Debian:11\x00curl": {unrated, rated}},
		meta:  frozenMeta(),
	}
	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{pkg("curl", "7.0.0", "Debian:11")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (the two records share CVE-2026-1)", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Advisory.ID != "DEBIAN-CVE-2026-1" {
		t.Fatalf("winner = %s, want the rated record to win the swap", f.Advisory.ID)
	}
	if !f.FrozenSince.Equal(d110Since) {
		t.Errorf("FrozenSince = %v after the swap, want %v", f.FrozenSince, d110Since)
	}
}

// Two providers never share a key (the build refuses it), but a hand-built
// database could; the earlier date wins, because understating staleness is
// the misleading direction (D12).
func TestFrozenKeys_EarlierDateWinsOnConflict(t *testing.T) {
	later := d110Since.AddDate(0, 1, 0)
	got, err := frozenKeys(fakeStore{meta: store.Meta{Providers: map[string]store.Provenance{
		"a": {Frozen: map[string]time.Time{"Debian:11": later}},
		"b": {Frozen: map[string]time.Time{"Debian:11": d110Since}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if !got["Debian:11"].Equal(d110Since) {
		t.Errorf("frozenKeys[Debian:11] = %v, want the earlier %v", got["Debian:11"], d110Since)
	}
}
