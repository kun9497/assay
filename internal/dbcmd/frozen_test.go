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

// debianEOL is this build's D87 catalog: bullseye (Debian:11) with the given
// EOLFrom, bookworm (Debian:12) not past EOL as of carryToday.
func debianEOL(eol11 string) fakeEOLSource {
	return fakeEOLSource{name: "endoflife.date", rows: []store.EOLRelease{
		{DistroID: "debian", Release: "11", EOLFrom: eol11},
		{DistroID: "debian", Release: "12", EOLFrom: "2028-06-10"},
	}}
}

func buildWithEOL(t *testing.T, seedPath string, eol provider.EOLSource, ps ...provider.Provider) (string, int, string) {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "out.db")
	var errOut bytes.Buffer
	code := Update(context.Background(), dst, seedPath, "", false, ps, nil, nil, eol, io.Discard, &errOut)
	return dst, code, errOut.String()
}

// erosionSeed is the Debian:11 shape measured 2026-09-20: every record carried
// [Debian:11, Debian:12] until OSV's export dropped bullseye's entries.
// KEEP stays on Debian:11 so the key remains live. extra is T10's record to
// withdraw -- kept out of T8, whose Push would otherwise be refused for the
// withdrawal's own Debian:12 drop (25% of four), which is the guard working.
func erosionSeed(t *testing.T, extra ...advisory.Advisory) string {
	return carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Debian:11", "Debian:12"}, DataAsOf: seedFreezeTime},
	}, append([]advisory.Advisory{
		adv("DEBIAN-R1", affects("Debian:11", "libfoo"), affects("Debian:12", "libfoo")),
		adv("DEBIAN-R2", affects("Debian:11", "libfoo"), affects("Debian:12", "libfoo")),
		adv("DEBIAN-R3", affects("Debian:11", "libfoo"), affects("Debian:12", "libfoo")),
		adv("DEBIAN-KEEP", affects("Debian:11", "libbar")),
	}, extra...)...)
}

// eroded is the provider after the export dropped Debian:11: R1..R3 come back
// with Debian:12 only, KEEP is untouched, and nothing else is emitted.
func eroded() fakeProvider {
	return fakeProvider{name: "osv", covers: []string{"Debian:11", "Debian:12"}, advs: []advisory.Advisory{
		adv("DEBIAN-R1", affects("Debian:12", "libfoo")),
		adv("DEBIAN-R2", affects("Debian:12", "libfoo")),
		adv("DEBIAN-R3", affects("Debian:12", "libfoo")),
		adv("DEBIAN-KEEP", affects("Debian:11", "libbar")),
	}}
}

// T8. Debian:11-shaped erosion on a past-EOL key: every entry the export
// dropped is restored onto the record it was dropped from, the key is marked
// frozen from the seed's DataAsOf, and the publish guard accepts the result.
func TestCarryForward_T8_PastEOLErosionIsRestored(t *testing.T) {
	pinCarryClock(t)
	seedPath := erosionSeed(t)
	dst, code, logs := buildWithEOL(t, seedPath, debianEOL("2024-08-14"), eroded())
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	t.Logf("Update stderr:\n%s", logs)
	db, m := openOut(t, dst)

	if got, want := lookupIDs(t, db, "Debian:11", "libfoo"), []string{"DEBIAN-R1", "DEBIAN-R2", "DEBIAN-R3"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Debian:11, libfoo) = %v, want %v", got, want)
	}
	for _, id := range []string{"DEBIAN-R1", "DEBIAN-R2", "DEBIAN-R3"} {
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
	const restored = "Debian:11 (past EOL since 2024-08-14): restored its entry on 3 advisories re-emitted without it"
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

// T9. The same narrowing on a key NOT past EOL is the upstream correcting
// itself (Canonical's tracker, D85): nothing is restored and nothing is
// frozen. Both shapes of "not past EOL" are held -- a future EOLFrom, and no
// catalog row for the key at all.
func TestCarryForward_T9_LiveKeyNarrowingIsNotRestored(t *testing.T) {
	pinCarryClock(t)
	for _, tc := range []struct {
		name string
		eol  fakeEOLSource
	}{
		{"future EOLFrom", debianEOL("2031-06-30")},
		{"no row for the key", fakeEOLSource{name: "endoflife.date", rows: []store.EOLRelease{
			{DistroID: "debian", Release: "12", EOLFrom: "2028-06-10"},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst, code, logs := buildWithEOL(t, erosionSeed(t), tc.eol, eroded())
			if code != 0 {
				t.Fatalf("Update = %d, want 0:\n%s", code, logs)
			}
			db, m := openOut(t, dst)
			if got := lookupIDs(t, db, "Debian:11", "libfoo"); len(got) != 0 {
				t.Errorf("Lookup(Debian:11, libfoo) = %v, want none: the key is not past EOL", got)
			}
			if f := m.Providers["osv"].Frozen; len(f) != 0 {
				t.Errorf("Frozen = %v, want empty", f)
			}
		})
	}
}

// T8b. "Past EOL" is past the LAST of a row's end dates, not past EOLFrom
// alone. Debian 11's shape: security support ended 2024-08-14, Debian LTS
// carried it to 2026-08-31, and only after that did its OSV entries leave --
// both past, so the erosion is restored, and the line names the LTS end as
// the day the upstream stopped, not the earlier EOLFrom.
func TestCarryForward_T8b_PastEveryEndDateIsRestored(t *testing.T) {
	pinCarryClock(t)
	eol := fakeEOLSource{name: "endoflife.date", rows: []store.EOLRelease{
		{DistroID: "debian", Release: "11", EOLFrom: "2024-08-14", EOESFrom: "2026-08-31"},
		{DistroID: "debian", Release: "12", EOLFrom: "2028-06-10"},
	}}
	dst, code, logs := buildWithEOL(t, erosionSeed(t), eol, eroded())
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	db, m := openOut(t, dst)
	if got, want := lookupIDs(t, db, "Debian:11", "libfoo"), []string{"DEBIAN-R1", "DEBIAN-R2", "DEBIAN-R3"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Debian:11, libfoo) = %v, want %v", got, want)
	}
	if _, ok := m.Providers["osv"].Frozen["Debian:11"]; !ok {
		t.Errorf("Frozen = %v, want Debian:11", m.Providers["osv"].Frozen)
	}
	const restored = "Debian:11 (past EOL since 2026-08-31): restored its entry on 3 advisories re-emitted without it"
	if !strings.Contains(logs, restored) {
		t.Errorf("stderr lacks %q:\n%s", restored, logs)
	}
}

// T9c. A release past EOLFrom but still inside a later end date is still
// maintained -- Debian 12's shape: bookworm's security support ends
// 2026-06-10, its Debian LTS runs to 2028 -- so a narrowing on it is the
// upstream correcting itself and is not restored. Held for both later
// phases, EOES and EOAS.
func TestCarryForward_T9c_PastEOLFromButInsideLaterPhaseIsNotRestored(t *testing.T) {
	pinCarryClock(t)
	for _, tc := range []struct {
		name string
		row  store.EOLRelease
	}{
		{"EOESFrom in the future", store.EOLRelease{DistroID: "debian", Release: "11", EOLFrom: "2024-08-14", EOESFrom: "2028-06-30"}},
		{"EOASFrom in the future", store.EOLRelease{DistroID: "debian", Release: "11", EOLFrom: "2024-08-14", EOASFrom: "2028-06-30"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eol := fakeEOLSource{name: "endoflife.date", rows: []store.EOLRelease{
				tc.row,
				{DistroID: "debian", Release: "12", EOLFrom: "2028-06-10"},
			}}
			dst, code, logs := buildWithEOL(t, erosionSeed(t), eol, eroded())
			if code != 0 {
				t.Fatalf("Update = %d, want 0:\n%s", code, logs)
			}
			db, m := openOut(t, dst)
			if got := lookupIDs(t, db, "Debian:11", "libfoo"); len(got) != 0 {
				t.Errorf("Lookup(Debian:11, libfoo) = %v, want none: the release is still maintained", got)
			}
			if f := m.Providers["osv"].Frozen; len(f) != 0 {
				t.Errorf("Frozen = %v, want empty", f)
			}
		})
	}
}

// T10. A record the upstream stopped emitting ALTOGETHER is a withdrawal
// (D16), even under a past-EOL key: it is not inserted, while its siblings'
// dropped entries are still restored.
func TestCarryForward_T10_WithdrawalUnderPastEOLKeyStaysWithdrawn(t *testing.T) {
	pinCarryClock(t)
	r4 := adv("DEBIAN-R4", affects("Debian:11", "libfoo"), affects("Debian:12", "libfoo"))
	dst, code, logs := buildWithEOL(t, erosionSeed(t, r4), debianEOL("2024-08-14"), eroded())
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	db, _ := openOut(t, dst)
	for _, eco := range []string{"Debian:11", "Debian:12"} {
		if _, ok := record(t, db, eco, "libfoo", "DEBIAN-R4"); ok {
			t.Errorf("DEBIAN-R4 is back under %s; a record not re-emitted must stay withdrawn", eco)
		}
	}
	if got, want := lookupIDs(t, db, "Debian:11", "libfoo"), []string{"DEBIAN-R1", "DEBIAN-R2", "DEBIAN-R3"}; !slices.Equal(got, want) {
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
// nothing for a key that held still.
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
	)
	p := fakeProvider{name: "osv", covers: []string{"Debian:11", "Go", "npm"}, advs: []advisory.Advisory{
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-GO-2", affects("Go", "alpha")),
		adv("OSV-NPM-1", affects("npm", "left-pad")),
		adv("DEBIAN-R1", affects("npm", "left-pad-2")),
		adv("DEBIAN-R2", affects("Debian:11", "libfoo")),
		adv("DEBIAN-R5", affects("Debian:11", "libfoo")),
	}}
	eol := fakeEOLSource{name: "endoflife.date", rows: []store.EOLRelease{{DistroID: "debian", Release: "11", EOLFrom: "2024-08-14"}}}
	_, code, logs := buildWithEOL(t, seedPath, eol, p)
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	for _, want := range []string{
		"\nGo: 3 -> 2 advisories (-1)\n",
		"\nDebian:11: 2 -> 3 advisories (+1, frozen since 2026-06-30)\n",
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
