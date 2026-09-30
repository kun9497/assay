package dbcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// D110: entry-level restore, the shared-key refusal, batching, the per-key
// count lines. Every test drives dbcmd.Update -- the caller -- for the reason
// carryforward_test.go's header gives.
//
// The entry-level rule keys on a REAL distro because the past-EOL set is built
// through pkgmeta.Distro.Ecosystem() from the catalog rows, never by string
// surgery on key names: "debian"/"11" must come out as "Debian:11" through the
// same function a scan uses, or the fixture proves nothing about the lookup.

// carryToday is the pinned clock every EOL judgement below is made against.
var carryToday = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func pinCarryClock(t *testing.T) {
	t.Helper()
	prev := carryNow
	carryNow = func() time.Time { return carryToday }
	t.Cleanup(func() { carryNow = prev })
}

// The D87 rows the entry-level tests judge against, as endoflife.date
// published them (read from the ghcr artifacts 2026-09-29) except rhel6,
// which is a shape. Real rows rather than minimal ones, because the defect
// this suite was rewritten for was a rule fitted to a remembered row: D110
// first gated on the latest of a row's three dates on the claim that Debian
// 12 was past EOLFrom -- it is not; only EOASFrom had passed -- and the
// recovery build then restored nothing on Debian:11.
//
// Debian 11 is held in BOTH shapes the catalog has given it, because
// endoflife.date reshaped the Debian product between the 08-30 and 09-20
// artifacts: on 08-30 EOLFrom was the end of security support and EOESFrom
// the end of LTS; from 09-20 EOLFrom is the end of LTS, EOASFrom the end of
// security support and EOESFrom Freexian's ELTS. A rule that pins meaning to
// a column or a label per distro breaks on the next such reshape, which is
// why the rule reads EOLFrom -- the earliest "the distro itself stopped" in
// every shape seen -- and asks the data whether the key is still growing.
var (
	debian11Aug = store.EOLRelease{DistroID: "debian", Release: "11", EOLFrom: "2024-08-14", EOESFrom: "2026-08-31"}
	debian11Sep = store.EOLRelease{DistroID: "debian", Release: "11", EOLFrom: "2026-08-31", EOASFrom: "2024-08-14", EOESFrom: "2031-06-30"}
	debian12    = store.EOLRelease{DistroID: "debian", Release: "12", EOLFrom: "2028-06-30", EOASFrom: "2026-07-11", EOESFrom: "2033-06-30"}
	rhel6       = store.EOLRelease{DistroID: "rhel", Release: "6", EOLFrom: "2020-11-30", EOESFrom: "2024-06-30"}
	rhel7       = store.EOLRelease{DistroID: "rhel", Release: "7", EOLFrom: "2024-06-30", EOASFrom: "2019-08-06", EOESFrom: "2029-05-31"}
	amzn2       = store.EOLRelease{DistroID: "amzn", Release: "2", EOLFrom: "2026-06-30", EOASFrom: "2026-06-30"}
	ubuntu1604  = store.EOLRelease{DistroID: "ubuntu", Release: "16.04", EOLFrom: "2021-04-02", EOESFrom: "2026-04-02"}
)

// catalog is this build's EOL source holding rows.
func catalog(rows ...store.EOLRelease) fakeEOLSource {
	return fakeEOLSource{name: "endoflife.date", rows: rows}
}

func buildWithEOL(t *testing.T, seedPath string, eol provider.EOLSource, ps ...provider.Provider) (string, int, string) {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "out.db")
	var errOut bytes.Buffer
	code := Update(context.Background(), dst, seedPath, "", false, ps, nil, nil, eol, io.Discard, &errOut)
	return dst, code, errOut.String()
}

// erosionSeedOn is the Debian:11 shape measured 2026-09-20, for any provider
// and pair of release keys: every record carried [gone, stays] until the
// upstream dropped gone's entries. KEEP stays on gone so the key remains live.
// extra is T10's record to withdraw -- kept out of T8, whose Push would
// otherwise be refused for the withdrawal's own stays-key drop (25% of four),
// which is the guard working.
func erosionSeedOn(t *testing.T, name, gone, stays string, extra ...advisory.Advisory) string {
	return carrySeed(t, map[string]store.Provenance{
		name: {Ecosystems: []string{gone, stays}, DataAsOf: seedFreezeTime},
	}, append([]advisory.Advisory{
		adv("REC-R1", affects(gone, "libfoo"), affects(stays, "libfoo")),
		adv("REC-R2", affects(gone, "libfoo"), affects(stays, "libfoo")),
		adv("REC-R3", affects(gone, "libfoo"), affects(stays, "libfoo")),
		adv("REC-KEEP", affects(gone, "libbar")),
	}, extra...)...)
}

// erodedOn is the provider after the upstream dropped gone: R1..R3 come back
// with stays only, KEEP is untouched, and nothing else is emitted but extra.
// With no extra, every record it stores under gone the seed already held
// there -- the key is flat, which is what the entry-level rule requires.
func erodedOn(name, gone, stays string, extra ...advisory.Advisory) fakeProvider {
	return fakeProvider{name: name, covers: []string{gone, stays}, advs: append([]advisory.Advisory{
		adv("REC-R1", affects(stays, "libfoo")),
		adv("REC-R2", affects(stays, "libfoo")),
		adv("REC-R3", affects(stays, "libfoo")),
		adv("REC-KEEP", affects(gone, "libbar")),
	}, extra...)}
}

// erosionSeed and eroded are the event itself: OSV's Debian export dropping
// bullseye (Debian:11) from records that keep bookworm (Debian:12).
func erosionSeed(t *testing.T, extra ...advisory.Advisory) string {
	return erosionSeedOn(t, "osv", "Debian:11", "Debian:12", extra...)
}

func eroded() fakeProvider { return erodedOn("osv", "Debian:11", "Debian:12") }

// T8. The Debian:11 event itself, against the current catalog rows: every
// entry the export dropped is restored onto the record it was dropped from,
// the key is marked frozen from the seed's DataAsOf, the line names EOLFrom
// and says why the key counts as stopped, and the publish guard accepts the
// result.
func TestCarryForward_T8_PastEOLErosionIsRestored(t *testing.T) {
	pinCarryClock(t)
	seedPath := erosionSeed(t)
	dst, code, logs := buildWithEOL(t, seedPath, catalog(debian11Sep, debian12), eroded())
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	t.Logf("Update stderr:\n%s", logs)
	db, m := openOut(t, dst)

	if got, want := lookupIDs(t, db, "Debian:11", "libfoo"), []string{"REC-R1", "REC-R2", "REC-R3"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Debian:11, libfoo) = %v, want %v", got, want)
	}
	for _, id := range []string{"REC-R1", "REC-R2", "REC-R3"} {
		a, ok := record(t, db, "Debian:12", "libfoo", id)
		if !ok {
			t.Errorf("%s is not reachable under Debian:12", id)
			continue
		}
		if got, want := ecosOf(a), []string{"Debian:11", "Debian:12"}; !slices.Equal(got, want) {
			t.Errorf("%s affected = %v, want %v (the fresh Debian:12 entry plus the restored one)", id, got, want)
		}
	}
	if got := m.Providers["osv"].Frozen["Debian:11"]; !got.Equal(seedFreezeTime) {
		t.Errorf("Frozen[Debian:11] = %v, want the seed's DataAsOf %v", got, seedFreezeTime)
	}
	if _, ok := m.Providers["osv"].Frozen["Debian:12"]; ok {
		t.Error("Debian:12 is live and not past EOL; it must not be frozen")
	}
	const restored = "Debian:11 (past EOL since 2026-08-31, no record new to it this run): restored its entry on 3 advisories re-emitted without it, frozen since 2026-06-30\n"
	if !strings.Contains(logs, restored) {
		t.Errorf("stderr lacks %q:\n%s", restored, logs)
	}

	ref := liveRegistry(t)
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), seedPath, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push(seed) = %d, want 0:\n%s", code, errOut.String())
	}
	errOut.Reset()
	if code := Push(context.Background(), dst, ref, false, &out, &errOut); code != 0 {
		t.Errorf("Push(restored build) = %d, want 0:\n%s", code, errOut.String())
	}
}

// T9. A key with no catalog row at all is not past EOL: a missing row is not
// evidence the release ended, so the narrowing stands as the upstream's own
// correction and nothing is frozen -- even though the key is flat.
func TestCarryForward_T9_KeyWithNoCatalogRowIsNotRestored(t *testing.T) {
	pinCarryClock(t)
	dst, code, logs := buildWithEOL(t, erosionSeed(t), catalog(debian12), eroded())
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	db, m := openOut(t, dst)
	if got := lookupIDs(t, db, "Debian:11", "libfoo"); len(got) != 0 {
		t.Errorf("Lookup(Debian:11, libfoo) = %v, want none: the key has no catalog row", got)
	}
	if f := m.Providers["osv"].Frozen; len(f) != 0 {
		t.Errorf("Frozen = %v, want empty", f)
	}
}

// T9b. A key's narrowing is restored only when BOTH hold: the catalog puts
// the release past EOLFrom, and this run stored no record under the key that
// the seed did not already hold there. The second is the data saying whether
// the provider's feed still serves the release, which no column of the
// catalog says reliably across distros or across endoflife.date's reshapes.
// Measured on the first recovery run (36541185015): Debian:11 was flat at
// 2,562 records while Amazon Linux:2 (+119), Ubuntu:16.04:LTS (+2,526), Red
// Hat:6 (+752), SLES:15.SP3 (+1,799) and openSUSE Leap:15.6 (+14,963) were
// all still growing past their EOLFrom -- and every one of those five had its
// corrections "restored" by a dates-only rule.
//
// Each case is T8's erosion on that distro's keys; runExtra is what the
// provider emitted beyond it, seedExtra what the seed held beyond it. since
// is the date the stderr line must name; "" means nothing may be restored,
// frozen, or reported as past EOL.
func TestCarryForward_T9b_PastEOLFromAndFlat(t *testing.T) {
	pinCarryClock(t)
	for _, tc := range []struct {
		name, provider, gone, stays string
		row                         store.EOLRelease
		seedExtra, runExtra         []advisory.Advisory
		since                       string
	}{
		{
			name: "debian 11, 08-30 catalog shape, flat", provider: "osv",
			gone: "Debian:11", stays: "Debian:12", row: debian11Aug, since: "2024-08-14",
		},
		{
			name: "debian 11, 09-29 catalog shape, flat", provider: "osv",
			gone: "Debian:11", stays: "Debian:12", row: debian11Sep, since: "2026-08-31",
		},
		{
			name: "debian 11, one record new to the key", provider: "osv",
			gone: "Debian:11", stays: "Debian:12", row: debian11Sep,
			runExtra: []advisory.Advisory{adv("REC-NEW-1", affects("Debian:11", "libnew"))},
		},
		{
			// A record the seed held under another key only, re-emitted with
			// an entry under this one: new to the key, so the key is live.
			name: "debian 11, a held record gains the key", provider: "osv",
			gone: "Debian:11", stays: "Debian:12", row: debian11Sep,
			seedExtra: []advisory.Advisory{adv("REC-S1", affects("Debian:12", "libnew"))},
			runExtra:  []advisory.Advisory{adv("REC-S1", affects("Debian:11", "libnew"), affects("Debian:12", "libnew"))},
		},
		{
			name: "debian 12, EOLFrom 2028, flat", provider: "osv",
			gone: "Debian:12", stays: "Debian:13", row: debian12,
		},
		{
			name: "rhel 7, one record new to the key", provider: "Red Hat CSAF VEX",
			gone: "Red Hat:7", stays: "Red Hat:8", row: rhel7,
			runExtra: []advisory.Advisory{adv("REC-NEW-1", affects("Red Hat:7", "libnew"))},
		},
		{
			name: "rhel 6, flat", provider: "Red Hat CSAF VEX",
			gone: "Red Hat:6", stays: "Red Hat:8", row: rhel6, since: "2020-11-30",
		},
		{
			name: "amzn 2, flat", provider: "Amazon Linux ALAS",
			gone: "Amazon Linux:2", stays: "Amazon Linux:2023", row: amzn2, since: "2026-06-30",
		},
		{
			name: "amzn 2, one record new to the key", provider: "Amazon Linux ALAS",
			gone: "Amazon Linux:2", stays: "Amazon Linux:2023", row: amzn2,
			runExtra: []advisory.Advisory{adv("REC-NEW-1", affects("Amazon Linux:2", "libnew"))},
		},
		{
			name: "ubuntu 16.04, records new to the key", provider: "osv",
			gone: "Ubuntu:16.04:LTS", stays: "Ubuntu:18.04:LTS", row: ubuntu1604,
			runExtra: []advisory.Advisory{
				adv("REC-NEW-1", affects("Ubuntu:16.04:LTS", "libnew")),
				adv("REC-NEW-2", affects("Ubuntu:16.04:LTS", "libnew")),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seedPath := erosionSeedOn(t, tc.provider, tc.gone, tc.stays, tc.seedExtra...)
			dst, code, logs := buildWithEOL(t, seedPath, catalog(tc.row), erodedOn(tc.provider, tc.gone, tc.stays, tc.runExtra...))
			if code != 0 {
				t.Fatalf("Update = %d, want 0:\n%s", code, logs)
			}
			db, m := openOut(t, dst)
			got := lookupIDs(t, db, tc.gone, "libfoo")
			frozen := m.Providers[tc.provider].Frozen
			if tc.since == "" {
				if len(got) != 0 {
					t.Errorf("Lookup(%s, libfoo) = %v, want none: the narrowing is a correction", tc.gone, got)
				}
				if len(frozen) != 0 {
					t.Errorf("Frozen = %v, want empty", frozen)
				}
				if strings.Contains(logs, "(past EOL since ") {
					t.Errorf("stderr reports a restored past-EOL key:\n%s", logs)
				}
				return
			}
			if want := []string{"REC-R1", "REC-R2", "REC-R3"}; !slices.Equal(got, want) {
				t.Errorf("Lookup(%s, libfoo) = %v, want %v", tc.gone, got, want)
			}
			if since, ok := frozen[tc.gone]; !ok || !since.Equal(seedFreezeTime) || len(frozen) != 1 {
				t.Errorf("Frozen = %v, want only %s at the seed's DataAsOf %v", frozen, tc.gone, seedFreezeTime)
			}
			line := tc.gone + " (past EOL since " + tc.since + ", no record new to it this run): restored its entry on 3 advisories re-emitted without it"
			if !strings.Contains(logs, line) {
				t.Errorf("stderr lacks %q:\n%s", line, logs)
			}
		})
	}
}

// T10. A record the upstream stopped emitting ALTOGETHER is a withdrawal
// (D16), even under a past-EOL key: it is not inserted, while its siblings'
// dropped entries are still restored.
func TestCarryForward_T10_WithdrawalUnderPastEOLKeyStaysWithdrawn(t *testing.T) {
	pinCarryClock(t)
	r4 := adv("REC-R4", affects("Debian:11", "libfoo"), affects("Debian:12", "libfoo"))
	dst, code, logs := buildWithEOL(t, erosionSeed(t, r4), catalog(debian11Sep, debian12), eroded())
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	db, _ := openOut(t, dst)
	for _, eco := range []string{"Debian:11", "Debian:12"} {
		if _, ok := record(t, db, eco, "libfoo", "REC-R4"); ok {
			t.Errorf("REC-R4 is back under %s; a record not re-emitted must stay withdrawn", eco)
		}
	}
	if got, want := lookupIDs(t, db, "Debian:11", "libfoo"), []string{"REC-R1", "REC-R2", "REC-R3"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Debian:11, libfoo) = %v, want %v", got, want)
	}
	const withdrawn = "1 not re-emitted at all, left withdrawn (D16)"
	if !strings.Contains(logs, withdrawn) {
		t.Errorf("stderr lacks %q:\n%s", withdrawn, logs)
	}
}

// T11. Two providers declaring one key is refused before anything is carried,
// so "the key is live" always means one provider's word.
func TestCarryForward_T11_SharedKeyIsRefused(t *testing.T) {
	a := fakeProvider{name: "alpha-src", covers: []string{"Go", "npm"}, advs: []advisory.Advisory{adv("OSV-GO-1", affects("Go", "alpha"))}}
	b := fakeProvider{name: "beta-src", covers: []string{"Go"}, advs: []advisory.Advisory{adv("OSV-GO-2", affects("Go", "alpha"))}}
	dst, code, logs := build(t, "", a, b)
	if code != 2 {
		t.Fatalf("Update = %d, want 2:\n%s", code, logs)
	}
	const want = "error: providers alpha-src and beta-src both declare Go"
	if !strings.Contains(logs, want) {
		t.Errorf("stderr lacks %q:\n%s", want, logs)
	}
	if strings.Contains(logs, "both declare npm") {
		t.Errorf("npm is declared by one provider only and must not be named:\n%s", logs)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("a refused build left a database at %s (stat err=%v)", dst, err)
	}
}

// T12. No EOL rows this build (EOL_ENABLE=0): entry-level cannot judge any key
// past EOL, says so, and restores nothing -- while whole-key still carries.
func TestCarryForward_T12_NoEOLRowsSkipsEntryLevelOnly(t *testing.T) {
	pinCarryClock(t)
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Debian:11", "Debian:12", "Retired-Eco"}, DataAsOf: seedFreezeTime},
	},
		adv("DEBIAN-R1", affects("Debian:11", "libfoo"), affects("Debian:12", "libfoo")),
		adv("DEBIAN-KEEP", affects("Debian:11", "libbar")),
		adv("OSV-RET-1", affects("Retired-Eco", "beta")),
	)
	p := fakeProvider{name: "osv", covers: []string{"Debian:11", "Debian:12"}, advs: []advisory.Advisory{
		adv("DEBIAN-R1", affects("Debian:12", "libfoo")),
		adv("DEBIAN-KEEP", affects("Debian:11", "libbar")),
	}}
	dst, code, logs := buildWithEOL(t, seedPath, nil, p)
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	const skipped = "entry-level carry-forward skipped: this build has no end-of-life rows"
	if !strings.Contains(logs, skipped) {
		t.Errorf("stderr lacks %q:\n%s", skipped, logs)
	}
	db, m := openOut(t, dst)
	if got := lookupIDs(t, db, "Debian:11", "libfoo"); len(got) != 0 {
		t.Errorf("Lookup(Debian:11, libfoo) = %v, want none without EOL rows", got)
	}
	if got, want := lookupIDs(t, db, "Retired-Eco", "beta"), []string{"OSV-RET-1"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Retired-Eco, beta) = %v, want %v: whole-key must still carry", got, want)
	}
	if _, ok := m.Providers["osv"].Frozen["Retired-Eco"]; !ok {
		t.Errorf("Frozen = %v, want Retired-Eco", m.Providers["osv"].Frozen)
	}
	if _, ok := m.Providers["osv"].Frozen["Debian:11"]; ok {
		t.Error("Debian:11 frozen without EOL rows to judge it by")
	}
}

// T13. A seed one schema behind IS carried from: the carry reads the seed's
// by-id records, whose JSON did not move in the bump to 9, never its index,
// whose shape did. buildOldShapedSeed writes a REAL pre-D67 index -- patching
// only Meta.Schema over a current index (store's setSchemaForTest) would let
// an index walk pass too, and the test would hold nothing about which one ran.
func TestCarryForward_T13_PreviousSchemaSeedIsCarried(t *testing.T) {
	seedPath := filepath.Join(t.TempDir(), "seed.db")
	buildOldShapedSeed(t, seedPath, []advisory.Advisory{
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-RET-1", affects("Retired-Eco", "beta")),
		adv("OSV-SHARED-1", affects("Go", "alpha"), affects("Retired-Eco", "beta")),
	}, nil, store.SchemaVersion-1)
	// buildOldShapedSeed writes no provider provenance; add the one the carry
	// consults, keeping the old schema number and the old index shape.
	db, err := bolt.Open(seedPath, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		blob, err := json.Marshal(store.Meta{Schema: store.SchemaVersion - 1, Providers: map[string]store.Provenance{
			"osv": {Ecosystems: []string{"Go", "Retired-Eco"}, DataAsOf: seedFreezeTime},
		}})
		if err != nil {
			return err
		}
		return tx.Bucket([]byte("meta")).Put([]byte("meta"), blob)
	})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}

	dst, code, logs := build(t, seedPath, goOnly())
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	out, m := openOut(t, dst)
	if got, want := lookupIDs(t, out, "Retired-Eco", "beta"), []string{"OSV-RET-1", "OSV-SHARED-1"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Retired-Eco, beta) = %v, want %v from a v%d seed", got, want, store.SchemaVersion-1)
	}
	if got := m.Providers["osv"].Frozen["Retired-Eco"]; !got.Equal(seedFreezeTime) {
		t.Errorf("Frozen[Retired-Eco] = %v, want %v", got, seedFreezeTime)
	}
}

// T14. The nightly log prints one line per seed key whose count moved -- a
// live key's erosion is reported even though it is not reversed -- and
// nothing for a key that held still. Debian:11 is flat and past EOLFrom, so
// DEBIAN-R1's dropped entry is restored and the key frozen; DEBIAN-R6 is not
// re-emitted at all, a withdrawal, so the frozen key's count still moves.
func TestCarryForward_T14_PerKeyCountLines(t *testing.T) {
	pinCarryClock(t)
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Debian:11", "Go", "npm"}, DataAsOf: seedFreezeTime},
	},
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-GO-2", affects("Go", "alpha")),
		adv("OSV-GO-3", affects("Go", "alpha")),
		adv("OSV-NPM-1", affects("npm", "left-pad")),
		adv("DEBIAN-R1", affects("Debian:11", "libfoo"), affects("npm", "left-pad-2")),
		adv("DEBIAN-R2", affects("Debian:11", "libfoo")),
		adv("DEBIAN-R6", affects("Debian:11", "libfoo")),
	)
	p := fakeProvider{name: "osv", covers: []string{"Debian:11", "Go", "npm"}, advs: []advisory.Advisory{
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-GO-2", affects("Go", "alpha")),
		adv("OSV-NPM-1", affects("npm", "left-pad")),
		adv("DEBIAN-R1", affects("npm", "left-pad-2")),
		adv("DEBIAN-R2", affects("Debian:11", "libfoo")),
	}}
	_, code, logs := buildWithEOL(t, seedPath, catalog(debian11Sep), p)
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	for _, want := range []string{
		"\nGo: 3 -> 2 advisories (-1)\n",
		"\nDebian:11: 3 -> 2 advisories (-1, frozen since 2026-06-30)\n",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, logs)
		}
	}
	for _, line := range strings.Split(logs, "\n") {
		if strings.HasPrefix(line, "npm: ") {
			t.Errorf("npm held at 2 and must print no count line, got %q", line)
		}
	}
}

// T14b. The count lines are the nightly's erosion signal, so they print on
// every seeded build -- not only when some key needed carrying. No EOL rows
// and no retired key means nothing is carried, and a live key's loss must
// still be reported.
func TestCarryForward_T14b_CountLinesPrintWithNothingToCarry(t *testing.T) {
	pinCarryClock(t)
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go", "npm"}, DataAsOf: seedFreezeTime},
	},
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-GO-2", affects("Go", "alpha")),
		adv("OSV-GO-3", affects("Go", "alpha")),
		adv("OSV-NPM-1", affects("npm", "left-pad")),
	)
	p := fakeProvider{name: "osv", covers: []string{"Go", "npm"}, advs: []advisory.Advisory{
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-GO-2", affects("Go", "alpha")),
		adv("OSV-NPM-1", affects("npm", "left-pad")),
	}}
	_, code, logs := buildWithEOL(t, seedPath, nil, p)
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	if want := "\nGo: 3 -> 2 advisories (-1)\n"; !strings.Contains(logs, want) {
		t.Errorf("stderr lacks %q:\n%s", want, logs)
	}
	if strings.Contains(logs, "carried") && !strings.Contains(logs, "none carried") {
		t.Errorf("nothing should have been carried:\n%s", logs)
	}
}

// Merges are batched (D57's putBatchSize): a key of 2*putBatchSize+1 records
// reaches MergeAffected in more than one transaction, none over the batch
// size, and every record lands.
func TestCarryForward_MergesAreBatched(t *testing.T) {
	advs := []advisory.Advisory{adv("OSV-GO-1", affects("Go", "alpha"))}
	const n = 2*putBatchSize + 1
	for i := range n {
		advs = append(advs, adv("OSV-RET-"+strconv.Itoa(i), affects("Retired-Eco", "beta")))
	}
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go", "Retired-Eco"}, DataAsOf: seedFreezeTime},
	}, advs...)

	var sizes []int
	prev := mergeAffected
	mergeAffected = func(w *store.Bolt, as []advisory.Advisory) (int, error) {
		sizes = append(sizes, len(as))
		return prev(w, as)
	}
	t.Cleanup(func() { mergeAffected = prev })

	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{adv("OSV-GO-1", affects("Go", "alpha"))}}
	dst, code, logs := build(t, seedPath, p)
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	total := 0
	for _, s := range sizes {
		if s > putBatchSize {
			t.Errorf("a MergeAffected call carried %d records, over putBatchSize %d", s, putBatchSize)
		}
		total += s
	}
	if len(sizes) < 3 {
		t.Errorf("MergeAffected called %d time(s) with %v, want at least 3 batches for %d records", len(sizes), sizes, n)
	}
	if total != n {
		t.Errorf("MergeAffected saw %d records, want %d", total, n)
	}
	db, _ := openOut(t, dst)
	if got := len(lookupIDs(t, db, "Retired-Eco", "beta")); got != n {
		t.Errorf("Lookup(Retired-Eco, beta) returned %d, want %d", got, n)
	}
	if want := "carried " + strconv.Itoa(n) + " advisories from seed"; !strings.Contains(logs, want) {
		t.Errorf("stderr lacks %q:\n%s", want, logs)
	}
}
