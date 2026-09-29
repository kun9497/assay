package dbcmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// D110: whole-key carry-forward. Every test here drives dbcmd.Update (and
// Push where the claim is about the publish guard) — the caller — rather than
// the store helper the carry uses, because a helper covered and a call site
// nothing holds is the most repeated defect on this project (CLAUDE.md).
//
// "Go" and "Retired-Eco" collide with no package name, advisory ID or other
// field these tests assert on, and every assertion compares IDs out of Lookup
// or exact map values, never a substring of rendered output where another
// column could satisfy it.

// seedFreezeTime is the seed provider's DataAsOf — what a key's freeze time
// must be recorded as the first night it goes missing. Deliberately different
// from fakeProvider's own DataAsOf (2026-07-29) and from now, so each of the
// three plausible wrong answers is distinguishable.
var seedFreezeTime = time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)

func affects(eco, name string) advisory.Affected {
	return advisory.Affected{Ecosystem: eco, Name: name}
}

func adv(id string, aff ...advisory.Affected) advisory.Advisory {
	return advisory.Advisory{ID: id, Database: "OSV", Source: "osv", Kind: advisory.KindVulnerability, Affected: aff}
}

// carrySeed writes a finished database holding advs, with the given provider
// provenance, plus three NVD ratings so a Push of it and of a seeded build
// derived from it compare equal on ratings and the rating guard is never the
// thing refusing.
func carrySeed(t *testing.T, providers map[string]store.Provenance, advs ...advisory.Advisory) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutMany(advs); err != nil {
		t.Fatal(err)
	}
	for _, cve := range []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"} {
		if err := w.PutRating(advisory.Rating{CVE: cve, Source: "NVD"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{Providers: providers}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// t1Seed is the pre-retirement database: one provider "osv" covering Go and
// Retired-Eco, with one record (OSV-SHARED-1) affecting both.
func t1Seed(t *testing.T) string {
	return carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go", "Retired-Eco"}, DataAsOf: seedFreezeTime},
	},
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-GO-2", affects("Go", "alpha")),
		adv("OSV-SHARED-1", affects("Go", "alpha"), affects("Retired-Eco", "beta")),
		adv("OSV-RET-1", affects("Retired-Eco", "beta")),
		adv("OSV-RET-2", affects("Retired-Eco", "gamma")),
	)
}

// goOnly is the post-retirement osv run: Retired-Eco is no longer served, and
// the shared record comes back with its Go entry only.
func goOnly() fakeProvider {
	return fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-GO-2", affects("Go", "alpha")),
		adv("OSV-SHARED-1", affects("Go", "alpha")),
	}}
}

func build(t *testing.T, seedPath string, ps ...provider.Provider) (string, int, string) {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "out.db")
	var errOut bytes.Buffer
	code := Update(context.Background(), dst, seedPath, "", false, ps, nil, nil, nil, io.Discard, &errOut)
	return dst, code, errOut.String()
}

func mustBuild(t *testing.T, seedPath string, ps ...provider.Provider) string {
	t.Helper()
	dst, code, logs := build(t, seedPath, ps...)
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	return dst
}

func openOut(t *testing.T, path string) (*store.Bolt, store.Meta) {
	t.Helper()
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	m, err := db.Meta()
	if err != nil {
		t.Fatal(err)
	}
	return db, m
}

func lookupIDs(t *testing.T, db *store.Bolt, eco, name string) []string {
	t.Helper()
	as, err := db.Lookup(eco, name)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(as))
	for _, a := range as {
		ids = append(ids, a.ID)
	}
	slices.Sort(ids)
	return ids
}

func record(t *testing.T, db *store.Bolt, eco, name, id string) (advisory.Advisory, bool) {
	t.Helper()
	as, err := db.Lookup(eco, name)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range as {
		if a.ID == id {
			return a, true
		}
	}
	return advisory.Advisory{}, false
}

func ecosOf(a advisory.Advisory) []string {
	var out []string
	for _, aff := range a.Affected {
		out = append(out, aff.Ecosystem)
	}
	slices.Sort(out)
	return out
}

// T1. The retirement: the key survives the night its upstream went quiet, and
// the publish guard needs no --force.
func TestCarryForward_T1_RetiredKeySurvivesAndPublishes(t *testing.T) {
	seedPath := t1Seed(t)
	dst, code, logs := build(t, seedPath, goOnly())
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	t.Logf("Update stderr:\n%s", logs)
	db, m := openOut(t, dst)

	if got, want := lookupIDs(t, db, "Retired-Eco", "beta"), []string{"OSV-RET-1", "OSV-SHARED-1"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Retired-Eco, beta) = %v, want %v", got, want)
	}
	if got, want := lookupIDs(t, db, "Retired-Eco", "gamma"), []string{"OSV-RET-2"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Retired-Eco, gamma) = %v, want %v", got, want)
	}
	shared, ok := record(t, db, "Go", "alpha", "OSV-SHARED-1")
	if !ok {
		t.Fatal("OSV-SHARED-1 is not reachable under Go at all")
	}
	if got, want := ecosOf(shared), []string{"Go", "Retired-Eco"}; !slices.Equal(got, want) {
		t.Errorf("OSV-SHARED-1 affected ecosystems = %v, want %v (the live Go entry plus the carried one)", got, want)
	}
	if !slices.Contains(m.Providers["osv"].Ecosystems, "Retired-Eco") {
		t.Errorf("Providers[osv].Ecosystems = %v, want it to still declare Retired-Eco", m.Providers["osv"].Ecosystems)
	}
	if !slices.Contains(m.Ecosystems, "Retired-Eco") {
		t.Errorf("Meta.Ecosystems = %v, want Retired-Eco (Covers must still answer for it)", m.Ecosystems)
	}
	if got := m.Providers["osv"].Frozen["Retired-Eco"]; !got.Equal(seedFreezeTime) {
		t.Errorf("Frozen[Retired-Eco] = %v, want the seed's DataAsOf %v", got, seedFreezeTime)
	}
	if _, frozen := m.Providers["osv"].Frozen["Go"]; frozen {
		t.Error("Go was emitted this run and must not be frozen")
	}

	// The publish guard: seed first, then the carried build, no --force.
	ref := liveRegistry(t)
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), seedPath, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push(seed) = %d, want 0:\n%s", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	code = Push(context.Background(), dst, ref, false, &out, &errOut)
	if code != 0 {
		t.Errorf("Push(carried build) = %d, want 0:\n%s", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "is missing") {
		t.Errorf("the guard still reports a missing key:\n%s", errOut.String())
	}
	t.Logf("Push(carried build) stderr:\n%s", errOut.String())
}

// T2. Flapping heals: the key comes back with different advisories, and the
// fresh ones replace the frozen ones outright.
func TestCarryForward_T2_ReappearanceWinsAndUnfreezes(t *testing.T) {
	frozenDB := mustBuild(t, t1Seed(t), goOnly())

	back := fakeProvider{name: "osv", covers: []string{"Go", "Retired-Eco"}, advs: []advisory.Advisory{
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-SHARED-1", affects("Go", "alpha")),
		adv("OSV-RET-FRESH", affects("Retired-Eco", "beta")),
	}}
	dst := mustBuild(t, frozenDB, back)
	db, m := openOut(t, dst)

	if got, want := lookupIDs(t, db, "Retired-Eco", "beta"), []string{"OSV-RET-FRESH"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Retired-Eco, beta) = %v, want exactly the fresh %v", got, want)
	}
	if got := lookupIDs(t, db, "Retired-Eco", "gamma"); len(got) != 0 {
		t.Errorf("Lookup(Retired-Eco, gamma) = %v, want none (the frozen record is gone)", got)
	}
	if shared, ok := record(t, db, "Go", "alpha", "OSV-SHARED-1"); !ok || !slices.Equal(ecosOf(shared), []string{"Go"}) {
		t.Errorf("OSV-SHARED-1 = %v (found=%v), want only its fresh Go entry", ecosOf(shared), ok)
	}
	if f, ok := m.Providers["osv"].Frozen["Retired-Eco"]; ok {
		t.Errorf("Frozen[Retired-Eco] = %v survived the key's reappearance", f)
	}
}

// T3. R1: a provider that did not run carries nothing, and the guard refuses.
func TestCarryForward_T3_ProviderThatDidNotRunCarriesNothing(t *testing.T) {
	// Nine Go records to other's one, so losing other costs 10% of the total
	// — inside advisoryRegression's 20% total-drop tolerance. With two Go
	// records the first run of this test was refused by the TOTAL rule
	// ("advisories dropped from 3 to 2") before the provider rule was ever
	// reached, which proves nothing about R1's message.
	var goAdvs []advisory.Advisory
	for _, id := range []string{"OSV-GO-1", "OSV-GO-2", "OSV-GO-3", "OSV-GO-4", "OSV-GO-5", "OSV-GO-6", "OSV-GO-7", "OSV-GO-8", "OSV-GO-9"} {
		goAdvs = append(goAdvs, adv(id, affects("Go", "alpha")))
	}
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv":   {Ecosystems: []string{"Go"}, DataAsOf: seedFreezeTime},
		"other": {Ecosystems: []string{"Other-Eco"}, DataAsOf: seedFreezeTime},
	}, append(slices.Clone(goAdvs), adv("OTHER-1", affects("Other-Eco", "delta")))...)
	osvOnly := fakeProvider{name: "osv", covers: []string{"Go"}, advs: goAdvs}
	dst := mustBuild(t, seedPath, osvOnly)
	db, m := openOut(t, dst)

	if got := lookupIDs(t, db, "Other-Eco", "delta"); len(got) != 0 {
		t.Errorf("Lookup(Other-Eco, delta) = %v, want none: other did not run", got)
	}
	if slices.Contains(m.Ecosystems, "Other-Eco") {
		t.Errorf("Meta.Ecosystems = %v, want no Other-Eco", m.Ecosystems)
	}
	if _, ok := m.Providers["other"]; ok {
		t.Errorf("Providers has an entry for other, which did not run: %+v", m.Providers["other"])
	}

	ref := liveRegistry(t)
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), seedPath, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push(seed) = %d, want 0:\n%s", code, errOut.String())
	}
	errOut.Reset()
	if code := Push(context.Background(), dst, ref, false, &out, &errOut); code != 2 {
		t.Errorf("Push(build without other) = %d, want 2:\n%s", code, errOut.String())
	}
	const refusal = `published provider "other" is missing`
	if !strings.Contains(errOut.String(), refusal) {
		t.Errorf("the refusal does not say %q:\n%s", refusal, errOut.String())
	}
	t.Logf("Push(build without other) stderr:\n%s", errOut.String())
}

// T3b. R1, the other half: a provider whose Fetch fails aborts the build as it
// always did — nothing written, nothing carried.
func TestCarryForward_T3b_FailedFetchStillAborts(t *testing.T) {
	dst, code, logs := build(t, t1Seed(t), dyingProvider{name: "osv"})
	if code != 2 {
		t.Errorf("Update with a failing osv = %d, want 2:\n%s", code, logs)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("a failed build left a database at %s (stat err=%v)", dst, err)
	}
}

// T4. The freeze time is the FIRST night's, carried — not refreshed to the
// seed's newer DataAsOf, and not to now.
func TestCarryForward_T4_FreezeTimeIsStable(t *testing.T) {
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go", "Retired-Eco"}, DataAsOf: t1, Frozen: map[string]time.Time{"Retired-Eco": t0}},
	},
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-RET-1", affects("Retired-Eco", "beta")),
	)
	dst := mustBuild(t, seedPath, goOnly())
	_, m := openOut(t, dst)
	if got := m.Providers["osv"].Frozen["Retired-Eco"]; !got.Equal(t0) {
		t.Errorf("Frozen[Retired-Eco] = %v, want the first freeze time %v (not the seed's DataAsOf %v, not now)", got, t0, t1)
	}
}

// T5. db status names a frozen key and its date, and says nothing once healed.
func TestCarryForward_T5_StatusListsFrozenKeys(t *testing.T) {
	frozenDB := mustBuild(t, t1Seed(t), goOnly())
	var out, errOut bytes.Buffer
	if code := Status(frozenDB, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d:\n%s", code, errOut.String())
	}
	const want = "frozen:     Retired-Eco since 2026-06-30 (osv)"
	if !strings.Contains(out.String(), want+"\n") {
		t.Errorf("status does not carry %q:\n%s", want, out.String())
	}

	back := fakeProvider{name: "osv", covers: []string{"Go", "Retired-Eco"}, advs: []advisory.Advisory{
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-RET-FRESH", affects("Retired-Eco", "beta")),
	}}
	healed := mustBuild(t, frozenDB, back)
	out.Reset()
	if code := Status(healed, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d:\n%s", code, errOut.String())
	}
	if strings.Contains(out.String(), "frozen:") {
		t.Errorf("a healed database still prints a frozen line:\n%s", out.String())
	}
}

// T6. D16: a live key is never carried. A record the provider stopped emitting
// under Go is gone from Go — including one that ALSO affected the frozen key,
// which survives there with its frozen entry only.
//
// OSV-WD-BOTH is this spike's addition to the scenario as specified: without a
// record affecting both keys that the provider did NOT re-emit, "carry the
// live-key entries too" (m4) cannot be told apart from the design, because a
// Go-only withdrawn record is never enumerated under Retired-Eco at all.
func TestCarryForward_T6_LiveKeysAreNeverCarried(t *testing.T) {
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go", "Retired-Eco"}, DataAsOf: seedFreezeTime},
	},
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("GHSA-withdrawn", affects("Go", "alpha")),
		adv("OSV-WD-BOTH", affects("Go", "alpha"), affects("Retired-Eco", "beta")),
		adv("OSV-RET-1", affects("Retired-Eco", "beta")),
	)
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{
		adv("OSV-GO-1", affects("Go", "alpha")),
	}}
	dst := mustBuild(t, seedPath, p)
	db, _ := openOut(t, dst)

	if got, want := lookupIDs(t, db, "Go", "alpha"), []string{"OSV-GO-1"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Go, alpha) = %v, want only the re-emitted %v", got, want)
	}
	if got, want := lookupIDs(t, db, "Retired-Eco", "beta"), []string{"OSV-RET-1", "OSV-WD-BOTH"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Retired-Eco, beta) = %v, want %v", got, want)
	}
	if both, ok := record(t, db, "Retired-Eco", "beta", "OSV-WD-BOTH"); ok && !slices.Equal(ecosOf(both), []string{"Retired-Eco"}) {
		t.Errorf("OSV-WD-BOTH carried with %v, want its frozen Retired-Eco entry only", ecosOf(both))
	}
}

// T7. Negative control: no seed, nothing to carry, behaviour as before.
func TestCarryForward_T7_UnseededBuildCarriesNothing(t *testing.T) {
	dst := mustBuild(t, "", goOnly())
	db, m := openOut(t, dst)
	if got := lookupIDs(t, db, "Retired-Eco", "beta"); len(got) != 0 {
		t.Errorf("Lookup(Retired-Eco, beta) = %v on an unseeded build", got)
	}
	if slices.Contains(m.Ecosystems, "Retired-Eco") {
		t.Errorf("Meta.Ecosystems = %v on an unseeded build", m.Ecosystems)
	}
	if len(m.Providers["osv"].Frozen) != 0 {
		t.Errorf("Frozen = %v on an unseeded build", m.Providers["osv"].Frozen)
	}
}
