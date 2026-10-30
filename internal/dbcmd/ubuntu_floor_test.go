package dbcmd

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// withUbuntuFixStates builds a database whose osv provider covers the given
// Ubuntu keys and holds, under each, that many fix-less ranges carrying a
// fix state -- what the artifact holds, however it came to hold it (stamped
// this build, or carried forward from the seed by D110).
const recordsPerKey = 100

func withUbuntuFixStates(t *testing.T, perKey map[string]int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range perKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var as []advisory.Advisory
	for _, k := range keys {
		// recordsPerKey records under every key, perKey[k] of them with a
		// fix state: the record count stays put while the states move, so
		// the advisory-count guard cannot answer for this one.
		for i := 0; i < recordsPerKey; i++ {
			state := advisory.FixStateWontFix
			if i%2 == 1 {
				state = advisory.FixStateNotFixed
			}
			if i >= perKey[k] {
				state = ""
			}
			as = append(as, advisory.Advisory{
				ID: fmt.Sprintf("UBUNTU-CVE-%s-%d", strings.ReplaceAll(k, ":", "-"), i), Kind: advisory.KindVulnerability,
				Affected: []advisory.Affected{{Ecosystem: k, Name: "x", Ranges: []advisory.Range{{
					Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}, FixState: state,
				}}}},
			})
		}
		// A fixed range and an unstamped fix-less one, under every key:
		// neither is a tracker fix state and neither may be counted.
		as = append(as,
			advisory.Advisory{ID: "UBUNTU-FIXED-" + k, Kind: advisory.KindVulnerability, Affected: []advisory.Affected{{Ecosystem: k, Name: "x",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0"}}}}}}},
			advisory.Advisory{ID: "UBUNTU-UNSTAMPED-" + k, Kind: advisory.KindVulnerability, Affected: []advisory.Affected{{Ecosystem: k, Name: "x",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}}}}}},
		)
	}
	if err := w.PutMany(as); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt: time.Date(2026, 10, 30, 6, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{"osv": {
			DataAsOf: time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC), Ecosystems: keys, Records: len(as),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func pushFixStates(t *testing.T, ref string, perKey map[string]int) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Push(context.Background(), withUbuntuFixStates(t, perKey), ref, false, &out, &errOut)
	return code, errOut.String()
}

// D157 (audit A15), the publish half, per release. A tracker that loses part
// of itself still stamps something, so the build passes; only a comparison
// with the published artifact sees it. Per Ubuntu key, because a whole-total
// floor misses losing most single releases: on the 2026-10-27 database
// 22.04 held 712,232 of 2,041,922 fix states and 14.04 held 1,146, so only
// the two largest releases are a fifth of the total. The count is what the
// artifact holds, read from the database, so ranges D110 carried forward
// count like ranges this build stamped.
func TestPush_D157_RefusesToLoseOneReleasesFixStates(t *testing.T) {
	published := map[string]int{"Ubuntu:22.04:LTS": 70, "Ubuntu:24.04:LTS": 35, "Ubuntu:26.04:LTS": 6}
	for _, tc := range []struct {
		name     string
		incoming map[string]int
		code     int
	}{
		{"the newest release lost, the total barely moves", map[string]int{"Ubuntu:22.04:LTS": 70, "Ubuntu:24.04:LTS": 35, "Ubuntu:26.04:LTS": 0}, 2},
		{"one release under its floor", map[string]int{"Ubuntu:22.04:LTS": 70, "Ubuntu:24.04:LTS": 27, "Ubuntu:26.04:LTS": 6}, 2},
		{"one release exactly at its floor", map[string]int{"Ubuntu:22.04:LTS": 56, "Ubuntu:24.04:LTS": 28, "Ubuntu:26.04:LTS": 6}, 0},
		{"everything grows", map[string]int{"Ubuntu:22.04:LTS": 80, "Ubuntu:24.04:LTS": 40, "Ubuntu:26.04:LTS": 9}, 0},
		{"a release added", map[string]int{"Ubuntu:22.04:LTS": 70, "Ubuntu:24.04:LTS": 35, "Ubuntu:26.04:LTS": 6, "Ubuntu:26.10": 3}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref := liveRegistry(t)
			if code, errOut := pushFixStates(t, ref, published); code != 0 {
				t.Fatalf("seeding = %d (%s)", code, errOut)
			}
			if got := publishedMeta(t, ref).UbuntuFixStates; fmt.Sprint(got) != fmt.Sprint(published) {
				t.Fatalf("published UbuntuFixStates = %v, want %v counted from the database", got, published)
			}
			signPublished(t, ref)
			code, errOut := pushFixStates(t, ref, tc.incoming)
			if code != tc.code {
				t.Errorf("Push = %d, want %d (%s)", code, tc.code, errOut)
			}
			if tc.code == 2 && !strings.Contains(errOut, "Ubuntu fix states") {
				t.Errorf("stderr does not name the regression:\n%s", errOut)
			}
		})
	}
}

// An artifact published before the annotation existed is still compared: its
// layer is unpacked once and counted, the same baseline path the advisory and
// rating annotations already take, so the first nightly after D157 lands is
// held too.
func TestPush_D157_AnArtifactWithoutTheAnnotationIsCountedFromItsLayer(t *testing.T) {
	ref := liveRegistry(t)
	publishLegacy(t, ref, withUbuntuFixStates(t, map[string]int{"Ubuntu:22.04:LTS": 10}))
	if got := publishedMeta(t, ref).UbuntuFixStates; got != nil {
		t.Fatalf("published UbuntuFixStates = %v, want nil: the artifact predates the annotation", got)
	}
	signPublished(t, ref)
	code, errOut := pushFixStates(t, ref, map[string]int{"Ubuntu:22.04:LTS": 2})
	if code != 2 || !strings.Contains(errOut, "Ubuntu fix states") {
		t.Errorf("Push = %d, want 2 against the baseline unpacked from the layer (%s)", code, errOut)
	}
}

// A database that covers no Ubuntu key records an empty count -- the
// annotation is written, so a later push need not unpack it -- and is never
// refused for Ubuntu.
func TestPush_D157_NoUbuntuCoverageRecordsAnEmptyCount(t *testing.T) {
	ref := liveRegistry(t)
	seed(t, ref, time.Time{}, 0)
	got := publishedMeta(t, ref).UbuntuFixStates
	if got == nil || len(got) != 0 {
		t.Errorf("published UbuntuFixStates = %v, want an empty, present count", got)
	}
}

// publishLegacy publishes dbPath as an artifact published before D157: every
// annotation the publisher writes today except the Ubuntu fix-state count.
func publishLegacy(t *testing.T, ref, dbPath string) {
	t.Helper()
	m, err := artifactMetaFromDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	m.UbuntuFixStates = nil
	img, err := dbartifact.Pack(dbPath, m)
	if err != nil {
		t.Fatal(err)
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
}

// ubuntuOnly is a provider serving fix-stated Ubuntu records under the keys
// it covers, nothing else.
type ubuntuOnly struct {
	advs   []advisory.Advisory
	covers []string
}

func (u ubuntuOnly) Name() string { return "osv" }
func (u ubuntuOnly) Fetch(_ context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	for _, a := range u.advs {
		if err := emit(a); err != nil {
			return store.Provenance{}, err
		}
	}
	return store.Provenance{Ecosystems: u.covers, Source: "x", DataAsOf: time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC), Records: len(u.advs)}, nil
}

func stampedEntry(eco, pkg string) advisory.Affected {
	return advisory.Affected{Ecosystem: eco, Name: pkg, Ranges: []advisory.Range{{
		Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}, FixState: advisory.FixStateWontFix}}}
}

// D110 and D157 together (branch review wf_4cdf11d7-722). When OSV stops
// serving an Ubuntu release, D110 carries its records forward from the seed,
// fix states included, and the artifact loses nothing. The first version of
// D157 counted only what this build stamped, so the carried release's states
// were missing from the count and every nightly after was refused. The count
// is read from the database now, and the carried build publishes.
func TestPush_D157_AReleaseCarriedForwardKeepsItsFixStates(t *testing.T) {
	live := []advisory.Advisory{
		adv("UBUNTU-D157-A", stampedEntry("Ubuntu:22.04:LTS", "a")),
		adv("UBUNTU-D157-B", stampedEntry("Ubuntu:22.04:LTS", "b")),
	}
	seedAdvs := append([]advisory.Advisory(nil), live...)
	for _, n := range []string{"c", "d", "e", "f", "g", "h", "i", "j"} {
		seedAdvs = append(seedAdvs, adv("UBUNTU-D157-OLD-"+n, stampedEntry("Ubuntu:20.04:LTS", n)))
	}
	seedPath := carrySeed(t, map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Ubuntu:20.04:LTS", "Ubuntu:22.04:LTS"}, DataAsOf: seedFreezeTime},
	}, seedAdvs...)
	// Tonight OSV no longer serves Ubuntu:20.04:LTS; D110 carries it.
	dst := mustBuild(t, seedPath, ubuntuOnly{advs: live, covers: []string{"Ubuntu:22.04:LTS"}})
	db, m := openOut(t, dst)
	db.Close()
	if m.Providers["osv"].Frozen["Ubuntu:20.04:LTS"].IsZero() {
		t.Fatal("Ubuntu:20.04:LTS was not carried forward; the fixture does not exercise D110")
	}

	ref := liveRegistry(t)
	var out, errOut bytes.Buffer
	if code := Push(context.Background(), seedPath, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Push(seed) = %d\n%s", code, errOut.String())
	}
	signPublished(t, ref)
	errOut.Reset()
	if code := Push(context.Background(), dst, ref, false, &out, &errOut); code != 0 {
		t.Errorf("Push(carried build) = %d, want 0: the carried release kept its 8 fix states\n%s", code, errOut.String())
	}
}
