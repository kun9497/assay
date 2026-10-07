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

// T6. D16: a live key is never carried, and neither is a withdrawal the
// provider made observable. A record the provider stopped emitting under Go
// is gone from Go. OSV-WD-BOTH ALSO affected the frozen key, but it affected
// Go too, which the provider still serves -- so its absence tonight is the
// provider withdrawing it, not the key going quiet, and it is not carried
// under Retired-Eco either. OSV-RET-1 affected only the frozen key: nothing
// tonight could say whether it was withdrawn, so it is carried.
//
// OSV-MOVED is what keeps "carry the live-key entries too" (m4) visible now
// that OSV-WD-BOTH is not carried at all: it is re-emitted with its Go entry
// moved to another package, so carrying the seed's Go entry would put it back
// under Go/alpha.
func TestCarryForward_T6_LiveKeysAreNeverCarried(t *testing.T) {
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go", "Retired-Eco"}, DataAsOf: seedFreezeTime},
	},
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("GHSA-withdrawn", affects("Go", "alpha")),
		adv("OSV-WD-BOTH", affects("Go", "alpha"), affects("Retired-Eco", "beta")),
		adv("OSV-MOVED", affects("Go", "alpha"), affects("Retired-Eco", "beta")),
		adv("OSV-RET-1", affects("Retired-Eco", "beta")),
	)
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-MOVED", affects("Go", "gamma")),
	}}
	dst, code, logs := build(t, seedPath, p)
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	db, _ := openOut(t, dst)

	if got, want := lookupIDs(t, db, "Go", "alpha"), []string{"OSV-GO-1"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Go, alpha) = %v, want only the re-emitted %v", got, want)
	}
	if got, want := lookupIDs(t, db, "Retired-Eco", "beta"), []string{"OSV-MOVED", "OSV-RET-1"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Retired-Eco, beta) = %v, want %v: OSV-WD-BOTH was withdrawn under a key osv still serves", got, want)
	}
	if _, ok := record(t, db, "Go", "alpha", "OSV-WD-BOTH"); ok {
		t.Error("OSV-WD-BOTH is back under Go")
	}
	const line = "osv emitted nothing for Retired-Eco; carried 2 advisories from seed"
	const withdrawn = "; 1 not re-emitted despite affecting a key osv still serves, left withdrawn (D16)\n"
	if !strings.Contains(logs, line) || !strings.Contains(logs, withdrawn) {
		t.Errorf("stderr lacks %q ... %q:\n%s", line, withdrawn, logs)
	}
}

// T6b. The withdrawal T6 drops has to be observable by the provider that ran:
// a seed record whose other entry is under ANOTHER provider's live key was
// never that provider's to re-emit, so its absence says nothing and it is
// carried like any record under the frozen key.
func TestCarryForward_T6b_OtherProvidersLiveKeyIsNotAWithdrawal(t *testing.T) {
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv":      {Ecosystems: []string{"Go", "Retired-Eco"}, DataAsOf: seedFreezeTime},
		"beta-src": {Ecosystems: []string{"Other-Eco"}, DataAsOf: seedFreezeTime},
	},
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("OSV-CROSS", affects("Retired-Eco", "beta"), affects("Other-Eco", "delta")),
		adv("BETA-1", affects("Other-Eco", "delta")),
	)
	osv := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{adv("OSV-GO-1", affects("Go", "alpha"))}}
	beta := fakeProvider{name: "beta-src", covers: []string{"Other-Eco"}, advs: []advisory.Advisory{adv("BETA-1", affects("Other-Eco", "delta"))}}
	dst, code, logs := build(t, seedPath, osv, beta)
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	db, _ := openOut(t, dst)
	if got, want := lookupIDs(t, db, "Retired-Eco", "beta"), []string{"OSV-CROSS"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(Retired-Eco, beta) = %v, want %v", got, want)
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

// D115. A rename the provider declares is not a stopped feed. Every test here
// drives Update, the caller, for the reason this file's header gives.
//
// "Old:Spelling" and "New:Spelling" share no substring with each other or
// with any ID, package or provider name asserted on here; the real
// "Echo:PyPi"/"Echo:PyPI" pair gets its own test below, asserted on whole
// rendered lines so the one-letter difference cannot be satisfied by the
// other spelling.

// renamingProvider is fakeProvider plus a Provenance.Renamed, the shape
// osv.Fetch returns when its static table names a key it now emits.
type renamingProvider struct {
	fakeProvider
	renamed map[string]string
}

func (r renamingProvider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	prov, err := r.fakeProvider.Fetch(ctx, emit)
	prov.Renamed = r.renamed
	return prov, err
}

// renameSeed is the seed the night after the upstream renamed old to new:
// the provider declared both, two records carry an entry under each (the
// 445 of the 2026-10-04 measurement) and one only under old (the 22).
func renameSeed(t *testing.T, old, new string) string {
	return carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go", new, old}, DataAsOf: seedFreezeTime},
	},
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("ECHO-DUP-1", affects(old, "requests"), affects(new, "requests")),
		adv("ECHO-DUP-2", affects(old, "urllib3"), affects(new, "urllib3")),
		adv("ECHO-ORPHAN-1", affects(old, "gitpython")),
	)
}

// renamedRun is the provider after the rename: new only, the two shared
// records re-emitted without their old entries, the orphan gone.
func renamedRun(old, new string, renamed map[string]string) renamingProvider {
	return renamingProvider{
		fakeProvider: fakeProvider{name: "osv", covers: []string{"Go", new}, advs: []advisory.Advisory{
			adv("OSV-GO-1", affects("Go", "alpha")),
			adv("ECHO-DUP-1", affects(new, "requests")),
			adv("ECHO-DUP-2", affects(new, "urllib3")),
		}},
		renamed: renamed,
	}
}

// T15. The declaration with its successor live: the old key is not carried,
// not frozen, no longer declared, and the count line says why with the seed's
// count and how many of those records the successor already holds.
func TestCarryForward_T15_DeclaredRenameIsNotCarried(t *testing.T) {
	const old, new = "Old:Spelling", "New:Spelling"
	dst, code, logs := build(t, renameSeed(t, old, new), renamedRun(old, new, map[string]string{old: new}))
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	t.Logf("Update stderr:\n%s", logs)
	db, m := openOut(t, dst)

	for _, pkg := range []string{"requests", "urllib3", "gitpython"} {
		if got := lookupIDs(t, db, old, pkg); len(got) != 0 {
			t.Errorf("Lookup(%s, %s) = %v, want none: a declared rename is not carried", old, pkg, got)
		}
	}
	if a, ok := record(t, db, new, "requests", "ECHO-DUP-1"); !ok || !slices.Equal(ecosOf(a), []string{new}) {
		t.Errorf("ECHO-DUP-1 = %v (found=%v), want only its fresh %s entry", ecosOf(a), ok, new)
	}
	if f, ok := m.Providers["osv"].Frozen[old]; ok {
		t.Errorf("Frozen[%s] = %v, want no entry: a spelling is not a stopped feed", old, f)
	}
	if slices.Contains(m.Providers["osv"].Ecosystems, old) || slices.Contains(m.Ecosystems, old) {
		t.Errorf("osv still declares %s: Providers=%v Meta=%v", old, m.Providers["osv"].Ecosystems, m.Ecosystems)
	}
	if got := m.Providers["osv"].Renamed[old]; got != new {
		t.Errorf("stored Renamed[%s] = %q, want %q (db status and the annotation read it)", old, got, new)
	}
	const line = "\nOld:Spelling: renamed to New:Spelling by osv, not carried (3 seed records, 2 also under New:Spelling) (D115)\n"
	if !strings.Contains(logs, line) {
		t.Errorf("stderr lacks %q:\n%s", line, logs)
	}
	for _, not := range []string{"osv emitted nothing for Old:Spelling", "\nOld:Spelling: 3 -> "} {
		if strings.Contains(logs, not) {
			t.Errorf("stderr still reports the rename as %q:\n%s", not, logs)
		}
	}
}

// T15b. The same fixture with no declaration: the key is carried and frozen
// exactly as D110 always did. This pins that the declaration -- not anything
// else about the fixture -- is what T15's behaviour depends on.
func TestCarryForward_T15b_UndeclaredRenameIsCarriedAndFrozen(t *testing.T) {
	const old, new = "Old:Spelling", "New:Spelling"
	dst, code, logs := build(t, renameSeed(t, old, new), renamedRun(old, new, nil))
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	db, m := openOut(t, dst)
	if got, want := lookupIDs(t, db, old, "gitpython"), []string{"ECHO-ORPHAN-1"}; !slices.Equal(got, want) {
		t.Errorf("Lookup(%s, gitpython) = %v, want %v", old, got, want)
	}
	if got := m.Providers["osv"].Frozen[old]; !got.Equal(seedFreezeTime) {
		t.Errorf("Frozen[%s] = %v, want %v", old, got, seedFreezeTime)
	}
	if strings.Contains(logs, "renamed to") {
		t.Errorf("an undeclared key reports a rename:\n%s", logs)
	}
}

// T15c. A declaration whose successor is not live under the declaring provider
// is inert: the key is carried and frozen as a stopped feed, and the log says
// the declaration was not applied. Two shapes -- the successor declared by
// nobody this run, and declared by another provider -- because "renamed" is a
// claim the declaring provider makes about its OWN keys; a successor someone
// else serves says nothing about where this provider's data went.
func TestCarryForward_T15c_DeclarationWithoutLiveSuccessorIsInert(t *testing.T) {
	const old, new = "Old:Spelling", "New:Spelling"
	for _, tc := range []struct {
		name   string
		target string
		extra  []provider.Provider
	}{
		{"successor not live at all", "Gone:Spelling", nil},
		{"successor live under another provider", "Elsewhere:Spelling", []provider.Provider{
			fakeProvider{name: "other-src", covers: []string{"Elsewhere:Spelling"}, advs: []advisory.Advisory{
				adv("OTHER-1", affects("Elsewhere:Spelling", "delta")),
			}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := append([]provider.Provider{renamedRun(old, new, map[string]string{old: tc.target})}, tc.extra...)
			dst, code, logs := build(t, renameSeed(t, old, new), ps...)
			if code != 0 {
				t.Fatalf("Update = %d, want 0:\n%s", code, logs)
			}
			db, m := openOut(t, dst)
			if got, want := lookupIDs(t, db, old, "gitpython"), []string{"ECHO-ORPHAN-1"}; !slices.Equal(got, want) {
				t.Errorf("Lookup(%s, gitpython) = %v, want %v: an inert declaration carries as before", old, got, want)
			}
			if got := m.Providers["osv"].Frozen[old]; !got.Equal(seedFreezeTime) {
				t.Errorf("Frozen[%s] = %v, want %v", old, got, seedFreezeTime)
			}
			line := "osv declares Old:Spelling renamed to " + tc.target + ", which osv does not declare this run; carried and frozen as a stopped key instead (D115)\n"
			if !strings.Contains(logs, line) {
				t.Errorf("stderr lacks %q:\n%s", line, logs)
			}
			if strings.Contains(logs, "not carried (") {
				t.Errorf("an inert declaration was applied:\n%s", logs)
			}
			// An unapplied declaration must not outlive the build that declined
			// it: left in the provenance it would reach the annotation and
			// `db status`, which would then list the key as renamed on the
			// same line as it is frozen.
			if to, ok := m.Providers["osv"].Renamed[old]; ok {
				t.Errorf("Renamed[%s] = %q survived an inert declaration; want it dropped", old, to)
			}
		})
	}
}

// T15d. The real pair, end to end: Update applies OSV's Echo declaration and
// db status then lists it under renamed: and no longer under frozen:, which
// is where the seed (frozen since 2026-08-19 in production) had it.
func TestCarryForward_T15d_EchoRenameLeavesFrozenForRenamed(t *testing.T) {
	const old, new = "Echo:PyPi", "Echo:PyPI"
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go", new, old}, DataAsOf: seedFreezeTime,
			Frozen: map[string]time.Time{old: seedFreezeTime}},
	},
		adv("OSV-GO-1", affects("Go", "alpha")),
		adv("ECHO-DUP-1", affects(old, "requests"), affects(new, "requests")),
		adv("ECHO-ORPHAN-1", affects(old, "gitpython")),
	)
	p := renamingProvider{
		fakeProvider: fakeProvider{name: "osv", covers: []string{"Go", new}, advs: []advisory.Advisory{
			adv("OSV-GO-1", affects("Go", "alpha")),
			adv("ECHO-DUP-1", affects(new, "requests")),
		}},
		renamed: map[string]string{old: new},
	}
	dst, code, logs := build(t, seedPath, p)
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	if want := "\nEcho:PyPi: renamed to Echo:PyPI by osv, not carried (2 seed records, 1 also under Echo:PyPI) (D115)\n"; !strings.Contains(logs, want) {
		t.Errorf("stderr lacks %q:\n%s", want, logs)
	}
	var out, errOut bytes.Buffer
	if code := Status(dst, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d:\n%s", code, errOut.String())
	}
	if want := "\nrenamed:    Echo:PyPi -> Echo:PyPI (osv)\n"; !strings.Contains(out.String(), want) {
		t.Errorf("status lacks %q:\n%s", want, out.String())
	}
	if strings.Contains(out.String(), "frozen:") {
		t.Errorf("status still lists a frozen key after the rename was applied:\n%s", out.String())
	}
}

// T15e. A renamed key the seed declared but held no record under still
// leaves the declared coverage, and that is said rather than silent -- no
// count line would otherwise mention a key with no seed records at all.
func TestCarryForward_T15e_RenamedKeyWithNoSeedRecordsIsStillReported(t *testing.T) {
	const old, new = "Old:Spelling", "New:Spelling"
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go", new, old}, DataAsOf: seedFreezeTime},
	}, adv("OSV-GO-1", affects("Go", "alpha")))
	p := renamingProvider{
		fakeProvider: fakeProvider{name: "osv", covers: []string{"Go", new}, advs: []advisory.Advisory{
			adv("OSV-GO-1", affects("Go", "alpha")),
			adv("ECHO-NEW-1", affects(new, "requests")),
		}},
		renamed: map[string]string{old: new},
	}
	_, code, logs := build(t, seedPath, p)
	if code != 0 {
		t.Fatalf("Update = %d, want 0:\n%s", code, logs)
	}
	const line = "\nOld:Spelling: renamed to New:Spelling by osv, not carried (0 seed records, 0 also under New:Spelling) (D115)\n"
	if !strings.Contains(logs, line) {
		t.Errorf("stderr lacks %q:\n%s", line, logs)
	}
}
