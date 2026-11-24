package dbcmd

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

var frozenEarlier = time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)

// D110 revised 2026-11-24. OSV withdrew every Debian record whose only release
// was bullseye, three months after it stopped serving bullseye. Under a key the
// seed already held frozen, a record not re-emitted is kept, and only there.
func TestCarryForward_AWithdrawalUnderAFrozenReleaseIsKept(t *testing.T) {
	pinCarryClock(t)
	frozen := map[string]time.Time{"Debian:11": frozenEarlier}
	seed := func(f map[string]time.Time) string {
		return carrySeed(t, map[string]store.Provenance{
			"osv": {Ecosystems: []string{"Debian:11", "Debian:12"}, DataAsOf: seedFreezeTime, Frozen: f},
		},
			adv("REC-R1", affects("Debian:11", "libfoo"), affects("Debian:12", "libfoo")),
			adv("REC-ONLY", affects("Debian:11", "gpac")),
			adv("REC-BOTH", affects("Debian:11", "gpac"), affects("Debian:12", "gpac")),
			adv("REC-LIVE", affects("Debian:12", "gpac")),
			adv("REC-DLA", affects("Debian:11", "libbar")),
		)
	}
	flat := []advisory.Advisory{adv("REC-R1", affects("Debian:12", "libfoo")), adv("REC-DLA", affects("Debian:11", "libbar"))}
	for _, tc := range []struct {
		name   string
		frozen map[string]time.Time
		covers []string
		advs   []advisory.Advisory
		want   []string // Debian:11 gpac
		line   string
	}{
		{"frozen, still declared", frozen, []string{"Debian:11", "Debian:12"}, flat,
			[]string{"REC-BOTH", "REC-ONLY"}, "no record new to it this run): restored its entry on 1 advisories re-emitted without it, frozen since 2026-08-19; 2 not re-emitted at all, kept: the key was frozen and is served no more"},
		{"frozen, a remnant that grew", frozen, []string{"Debian:11", "Debian:12"}, []advisory.Advisory{adv("REC-R1", affects("Debian:12", "libfoo")), adv("REC-NEW", affects("Debian:11", "libnew"))},
			[]string{"REC-BOTH", "REC-ONLY"}, "kept: the key was frozen and is served no more"},
		{"frozen, declared no more", frozen, []string{"Debian:12"}, flat[:1],
			[]string{"REC-BOTH", "REC-ONLY"}, "carried 4 advisories from seed"},
		{"the first night it is flat", nil, []string{"Debian:11", "Debian:12"}, flat,
			nil, "2 not re-emitted at all, left withdrawn (D16)"},
		{"the first night it is not declared", nil, []string{"Debian:12"}, flat[:1],
			[]string{"REC-ONLY"}, "1 not re-emitted despite affecting a key osv still serves, left withdrawn (D16)"},
		// Ubuntu:25.10: frozen by one restored entry, and served all the same.
		{"frozen, but this run holds half of it", frozen, []string{"Debian:11", "Debian:12"}, []advisory.Advisory{adv("REC-R1", affects("Debian:11", "libfoo")), adv("REC-DLA", affects("Debian:11", "libbar"))},
			nil, "2 not re-emitted at all, left withdrawn (D16)"},
		{"the first night it is a remnant that grew", nil, []string{"Debian:11", "Debian:12"}, []advisory.Advisory{adv("REC-R1", affects("Debian:12", "libfoo")), adv("REC-NEW", affects("Debian:11", "libnew"))},
			nil, "left withdrawn (D16)"},
		{"another provider's freeze is not this one's", map[string]time.Time{"Debian:12": frozenEarlier}, []string{"Debian:11", "Debian:12"}, flat,
			nil, "left withdrawn (D16)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst, code, logs := buildWithEOL(t, seed(tc.frozen), catalog(debian11Sep, debian12),
				fakeProvider{name: "osv", covers: tc.covers, advs: tc.advs})
			if code != 0 {
				t.Fatalf("Update = %d:\n%s", code, logs)
			}
			db, m := openOut(t, dst)
			if got := lookupIDs(t, db, "Debian:11", "gpac"); !slices.Equal(got, tc.want) {
				t.Errorf("Lookup(Debian:11, gpac) = %v, want %v", got, tc.want)
			}
			// D16 on the live key, whatever the frozen one keeps.
			if got := lookupIDs(t, db, "Debian:12", "gpac"); len(got) != 0 {
				t.Errorf("Lookup(Debian:12, gpac) = %v, want none", got)
			}
			if !strings.Contains(logs, tc.line) {
				t.Errorf("stderr lacks %q:\n%s", tc.line, logs)
			}
			if since, ok := m.Providers["osv"].Frozen["Debian:11"]; tc.frozen["Debian:11"] == frozenEarlier && tc.want != nil && (!ok || !since.Equal(frozenEarlier)) {
				t.Errorf("frozen since %v, %v; want the seed's date", since, ok)
			}
		})
	}
}

// Nothing restored but a kept record is still a freeze.
func TestCarryForward_AKeptRecordAloneKeepsTheKeyFrozen(t *testing.T) {
	pinCarryClock(t)
	path := carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Debian:11", "Debian:12"}, DataAsOf: seedFreezeTime, Frozen: map[string]time.Time{"Debian:11": frozenEarlier}},
	}, adv("REC-ONLY", affects("Debian:11", "gpac")), adv("REC-ONLY2", affects("Debian:11", "ntp")), adv("REC-DLA", affects("Debian:11", "libbar")))
	dst, code, logs := buildWithEOL(t, path, catalog(debian11Sep, debian12),
		fakeProvider{name: "osv", covers: []string{"Debian:11", "Debian:12"}, advs: []advisory.Advisory{adv("REC-DLA", affects("Debian:11", "libbar"))}})
	if code != 0 {
		t.Fatalf("Update = %d:\n%s", code, logs)
	}
	_, m := openOut(t, dst)
	if since := m.Providers["osv"].Frozen["Debian:11"]; !since.Equal(frozenEarlier) {
		t.Errorf("frozen since %v, want %v", since, frozenEarlier)
	}
}

// A frozen key whose release has not ended is not a stopped one: a retired
// ecosystem's record withdrawn under a key still served stays withdrawn.
func TestCarryForward_AFrozenKeyThatIsNoEndedReleaseStillTakesWithdrawals(t *testing.T) {
	pinCarryClock(t)
	path := carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go", "Retired-Eco"}, DataAsOf: seedFreezeTime, Frozen: map[string]time.Time{"Retired-Eco": frozenEarlier}},
	}, adv("OSV-GO-1", affects("Go", "alpha")), adv("OSV-WD", affects("Go", "alpha"), affects("Retired-Eco", "beta")))
	dst, code, logs := buildWithEOL(t, path, catalog(debian11Sep, debian12),
		fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{adv("OSV-GO-1", affects("Go", "alpha"))}})
	if code != 0 {
		t.Fatalf("Update = %d:\n%s", code, logs)
	}
	db, _ := openOut(t, dst)
	if got := lookupIDs(t, db, "Retired-Eco", "beta"); len(got) != 0 {
		t.Errorf("Lookup(Retired-Eco, beta) = %v, want none", got)
	}
}
