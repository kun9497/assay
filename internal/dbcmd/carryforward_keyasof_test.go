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
// the CleanStart archive's stale Last-Modified -- Debian's own archive was
// eleven days fresher. Caller first (CLAUDE.md): Update, through the real
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
