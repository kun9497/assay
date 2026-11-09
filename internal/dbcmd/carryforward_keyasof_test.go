package dbcmd

import (
	"testing"
	"time"

	"github.com/kun9497/assay/internal/store"
)

// D113 revised (2026-11-09): a key's freeze date is the key's own archive date
// when the seed provider recorded one (Provenance.KeyAsOf), not the provider's
// DataAsOf. Debian:11 had been frozen "since 2026-08-19" on every artifact
// because osv's DataAsOf is the minimum across its archives and 2026-08-19 was
// the CleanStart archive's stale Last-Modified -- the seed was built 2026-08-30,
// so Debian's own archive was up to eleven days fresher (its Meta recorded no
// per-key date, so the exact gap is not recoverable). Caller first (CLAUDE.md): Update, through the real
// carry-forward, asserting the Frozen map it writes.

// keyArchiveTime is Retired-Eco's own archive date in the seed: later than the
// provider-wide seedFreezeTime (2026-06-30), so the two answers differ.
var keyArchiveTime = time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)

func TestCarryForward_FreezeDateIsTheKeysOwnArchiveDate(t *testing.T) {
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv": {
			Ecosystems: []string{"Go", "Retired-Eco"},
			DataAsOf:   seedFreezeTime,
			KeyAsOf:    map[string]time.Time{"Go": time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC), "Retired-Eco": keyArchiveTime},
		},
	},
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-RET-1", affects("Retired-Eco", "beta")),
	)
	dst, code, logs := build(t, seedPath, goOnly())
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	_, m := openOut(t, dst)
	if got := m.Providers["osv"].Frozen["Retired-Eco"]; !got.Equal(keyArchiveTime) {
		t.Errorf("Frozen[Retired-Eco] = %v, want the key's own archive date %v, not the provider's %v",
			got, keyArchiveTime, seedFreezeTime)
	}
	// The carried key is dated in KeyAsOf too, by its freeze: this run's
	// provider did not fetch it, so without this a reader falls back to the
	// provider's DataAsOf -- the stalest LIVE archive -- and the age gate
	// judges the frozen key by a date that is not its own.
	if got, ok := m.Providers["osv"].KeyAsOf["Retired-Eco"]; !ok || !got.Equal(keyArchiveTime) {
		t.Errorf("KeyAsOf[Retired-Eco] = %v (present %v), want the freeze date %v written for the carried key", got, ok, keyArchiveTime)
	}
	if _, ok := m.Providers["osv"].KeyAsOf["Go"]; ok {
		t.Error("KeyAsOf[Go] was written by carry-forward: a live key is dated by its provider, not by the carry")
	}
}

// freezeSince's second branch: the seed declared the key under ANOTHER
// provider name (a provider rename between two builds). The key's own archive
// date must still win over that provider's DataAsOf. Driven through the
// entry-level restore, because a whole-key carry needs the RUNNING provider to
// have declared the key in the seed and so never reaches this branch.
func TestCarryForward_RenamedSeedProviderStillDatesTheKeyByItsArchive(t *testing.T) {
	pinCarryClock(t)
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv-old": {
			Ecosystems: []string{"Debian:11", "Debian:12"},
			DataAsOf:   seedFreezeTime,
			KeyAsOf:    map[string]time.Time{"Debian:11": keyArchiveTime},
		},
	},
		adv("REC-R1", affects("Debian:11", "libfoo"), affects("Debian:12", "libfoo")),
		adv("REC-R2", affects("Debian:11", "libfoo"), affects("Debian:12", "libfoo")),
		adv("REC-R3", affects("Debian:11", "libfoo"), affects("Debian:12", "libfoo")),
		adv("REC-KEEP", affects("Debian:11", "libbar")),
	)
	dst, code, logs := buildWithEOL(t, seedPath, catalog(debian11Sep, debian12), eroded())
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	_, m := openOut(t, dst)
	if got := m.Providers["osv"].Frozen["Debian:11"]; !got.Equal(keyArchiveTime) {
		t.Errorf("Frozen[Debian:11] = %v, want the key's own archive date %v from the seed's renamed provider, not its DataAsOf %v",
			got, keyArchiveTime, seedFreezeTime)
	}
}

// An existing freeze is carried unchanged (D12: the FIRST night the data
// stopped), whatever KeyAsOf says on a later night: the per-key date refines
// where a freeze starts, it does not refresh one already recorded.
func TestCarryForward_AnExistingFreezeOutranksTheKeysOwnArchiveDate(t *testing.T) {
	firstFreeze := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv": {
			Ecosystems: []string{"Go", "Retired-Eco"},
			DataAsOf:   seedFreezeTime,
			KeyAsOf:    map[string]time.Time{"Retired-Eco": keyArchiveTime},
			Frozen:     map[string]time.Time{"Retired-Eco": firstFreeze},
		},
	},
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-RET-1", affects("Retired-Eco", "beta")),
	)
	dst, code, logs := build(t, seedPath, goOnly())
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	_, m := openOut(t, dst)
	if got := m.Providers["osv"].Frozen["Retired-Eco"]; !got.Equal(firstFreeze) {
		t.Errorf("Frozen[Retired-Eco] = %v, want the first freeze %v carried unchanged", got, firstFreeze)
	}
}
