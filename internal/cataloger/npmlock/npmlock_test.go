package npmlock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The lockfileVersion 3 shape, which is what npm 7+ writes.
func TestParse_V3PackagesObject(t *testing.T) {
	p := write(t, `{
	  "name": "app", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.11"},
	    "node_modules/@scope/pkg": {"version": "2.0.0"}
	  }
	}`)
	pkgs, stats, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, pk := range pkgs {
		got[pk.Name] = pk.Version
	}
	if got["lodash"] != "4.17.11" {
		t.Errorf("lodash = %q, want 4.17.11 (got %v)", got["lodash"], got)
	}
	// A scoped package keeps its scope: "pkg" alone is a different package,
	// and stripping the scope would match the wrong advisories.
	if got["@scope/pkg"] != "2.0.0" {
		t.Errorf("@scope/pkg = %q, want 2.0.0 (got %v)", got["@scope/pkg"], got)
	}
	if len(pkgs) != 2 {
		t.Errorf("cataloged %d packages, want 2 — the root entry is the project, "+
			"not a dependency", len(pkgs))
	}
	// The invariant every cataloger in this repo holds.
	if stats.Components != stats.Cataloged+stats.SkippedNoPURL+
		stats.SkippedNoVersion+stats.SkippedUnsupportedEcosystem {
		t.Errorf("Components (%d) != Cataloged (%d) + skips (%d/%d/%d)",
			stats.Components, stats.Cataloged, stats.SkippedNoPURL,
			stats.SkippedNoVersion, stats.SkippedUnsupportedEcosystem)
	}
}

// Name and Version are not enough to match anything - the matcher keys on
// Type, Ecosystem, and (for distro packages) Source. A typo here, such as
// Ecosystem: "npmjs", compiles, catalogs a Package, and simply never matches
// an advisory: no crash, no error, a confident wrong answer. Locations is
// checked too, since it is what --explain shows as the evidence for a
// finding (D10). gomod_test.go:71-82 asserts the same shape for its own
// cataloger.
func TestParse_CatalogedPackageCarriesMatchableFields(t *testing.T) {
	p := write(t, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.11"}
	  }
	}`)
	pkgs, _, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	pk := pkgs[0]
	if pk.Type != "npm" {
		t.Errorf("Type = %q, want npm", pk.Type)
	}
	if pk.Ecosystem != "npm" {
		t.Errorf("Ecosystem = %q, want npm", pk.Ecosystem)
	}
	// package-lock.json names no distro; D8's source/binary split is a distro
	// concern, and Source must stay nil rather than fabricate one.
	if pk.Source != nil {
		t.Errorf("Source = %+v, want nil", pk.Source)
	}
	if len(pk.Locations) != 1 || pk.Locations[0].Path != p {
		t.Errorf("Locations = %+v, want one entry naming %s", pk.Locations, p)
	}
}

// npm 6 wrote lockfileVersion 1 with a nested "dependencies" tree, and those
// files are still in real repositories. Reading only "packages" returns zero
// packages for them — a silent empty result, which is the defect this slice
// exists to remove, arriving through a different door.
func TestParse_V1NestedDependencies(t *testing.T) {
	p := write(t, `{
	  "name": "app", "lockfileVersion": 1,
	  "dependencies": {
	    "lodash": {"version": "4.17.11"},
	    "chalk": {
	      "version": "2.4.2",
	      "dependencies": {"ansi-styles": {"version": "3.2.1"}}
	    }
	  }
	}`)
	pkgs, _, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, pk := range pkgs {
		got[pk.Name] = pk.Version
	}
	for name, want := range map[string]string{
		"lodash": "4.17.11", "chalk": "2.4.2", "ansi-styles": "3.2.1",
	} {
		if got[name] != want {
			t.Errorf("%s = %q, want %q — nested dependencies must be walked (got %v)",
				name, got[name], want, got)
		}
	}
}

// catalogDependencies sorts at every level of the v1 tree via ONE sortedKeys()
// call reached through self-recursion, so a regression that deletes it breaks
// every level at once - a fixture with a single-key nested map (as an earlier
// version of this test used) cannot tell that apart from a fixture that only
// exercises the top level, because a one-key map has exactly one possible
// iteration order and "proves" nothing about sorting on its own; all of that
// version's detection came from the top level, and its comment claiming
// otherwise was wrong.
//
// Both levels here carry five keys each, declared out of sorted order, so
// each level independently needs Go's per-run randomized map iteration to
// land on fully-sorted order BY CHANCE to escape detection - 1-in-120 (5!)
// odds, per level, for a regression confined to that level alone. (This
// specific mutation - deleting the one shared sortedKeys() call - breaks both
// levels simultaneously, so escaping THIS mutation needs both draws to land
// sorted at once: on the order of 1-in-14400. A future regression that only
// mis-recurses one level, without touching the other, still gets the 1-in-120
// floor from that level by itself.)
//
// This can never be made deterministic - Go's map iteration order cannot be
// forced - only made negligible by key count. The FIXED code (sort.Strings)
// is fully deterministic; only the MUTANT's escape is probabilistic.
func TestParse_V1DependenciesSortedAtEveryLevel(t *testing.T) {
	p := write(t, `{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "zebra": {"version": "10.0.0"},
	    "mango": {"version": "9.0.0"},
	    "cherry": {
	      "version": "8.0.0",
	      "dependencies": {
	        "yak": {"version": "5.0.0"},
	        "iguana": {"version": "4.0.0"},
	        "gecko": {"version": "3.0.0"},
	        "elk": {"version": "2.0.0"},
	        "cat": {"version": "1.0.0"}
	      }
	    },
	    "banana": {"version": "7.0.0"},
	    "apple": {"version": "6.0.0"}
	  }
	}`)
	pkgs, _, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, pk := range pkgs {
		got = append(got, pk.Name)
	}
	// Top level sorted: apple, banana, cherry, mango, zebra. cherry's own
	// subtree (sorted: cat, elk, gecko, iguana, yak) is fully walked
	// immediately after cherry, before mango, since the walk recurses into
	// each entry as it is visited rather than breadth-first.
	want := []string{"apple", "banana", "cherry", "cat", "elk", "gecko", "iguana", "yak", "mango", "zebra"}
	if len(got) != len(want) {
		t.Fatalf("packages in order %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("packages in order %v, want %v (sorted at every level of the v1 tree)", got, want)
		}
	}
}

// A nested install ("node_modules/a/node_modules/b") is package b, not "a/b".
// Taking the whole key as the name produces a package nothing has advisories
// for, which is a silent miss.
func TestParse_NestedInstallPathNamesTheInnermostPackage(t *testing.T) {
	p := write(t, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"version": "1.0.0"},
	    "node_modules/a/node_modules/lodash": {"version": "4.17.11"}
	  }
	}`)
	pkgs, _, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	if pkgs[0].Name != "lodash" {
		t.Errorf("Name = %q, want lodash", pkgs[0].Name)
	}
	if pkgs[0].PURL != "pkg:npm/lodash@4.17.11" {
		t.Errorf("PURL = %q, want pkg:npm/lodash@4.17.11", pkgs[0].PURL)
	}
}

// Entries with nothing to match on are counted, never dropped. A dropped entry
// is invisible to the skip counters, which is worse than a counted skip
// because nothing in the report hints it existed (cyclonedx.go:37-41).
func TestParse_UnmatchableEntriesAreCountedNotDropped(t *testing.T) {
	p := write(t, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"version": "1.0.0"},
	    "node_modules/linked": {"link": true, "resolved": "../local"},
	    "node_modules/noversion": {},
	    "node_modules/real": {"version": "1.2.3"}
	  }
	}`)
	pkgs, stats, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("cataloged %d, want 1 (only 'real' is matchable)", len(pkgs))
	}
	// Three, not four: the "" root is the project itself, not a component, so
	// it is not counted at all — gomod does not count its `module` line and
	// cyclonedx does not count metadata.component either. Counting it put
	// NotEvaluated at 1 on every healthy npm scan and made
	// --fail-on-incomplete exit 2 where nothing was wrong.
	if stats.Components != 3 {
		t.Errorf("Components = %d, want 3 — the two unmatchable DEPENDENCIES are "+
			"counted, the root project is not a dependency at all", stats.Components)
	}
	if stats.SkippedNoVersion != 2 {
		t.Errorf("SkippedNoVersion = %d, want 2 (link, no-version — not the root)",
			stats.SkippedNoVersion)
	}
}

// Decoding a JSON object means ranging a Go map, and Go randomizes map range
// order per run - not insertion order, not the order keys appeared in the
// source file. A map range reaching the returned slice would make scan
// output vary between two runs of the exact same lockfile. Keys here are
// chosen so their sorted order differs from every other order the fixture is
// written in, so an unsorted range has 1-in-24 odds of passing by luck.
func TestParse_PackagesInSortedKeyOrder(t *testing.T) {
	p := write(t, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"version": "0.0.0"},
	    "node_modules/zebra": {"version": "1.0.0"},
	    "node_modules/mango": {"version": "3.0.0"},
	    "node_modules/apple": {"version": "2.0.0"},
	    "node_modules/banana": {"version": "4.0.0"}
	  }
	}`)
	pkgs, _, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, pk := range pkgs {
		got = append(got, pk.Name)
	}
	want := []string{"apple", "banana", "mango", "zebra"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("packages in order %v, want %v (sorted by install-path key)", got, want)
		}
	}
}

// A real lockfileVersion 2 file carries BOTH "packages" (npm's canonical,
// richer shape, introduced in v2) and "dependencies" (kept only for
// backward compatibility with npm 6 tooling that reads v1 files). The two
// are populated from the same resolution, but nothing stops them from
// disagreeing - most often because "dependencies" was left over from an
// npm 6 -> 7 upgrade and never regenerated. "packages" must win: it is the
// shape npm itself reads when both are present.
func TestParse_PackagesObjectTakesPrecedenceOverDependencies(t *testing.T) {
	p := write(t, `{
	  "lockfileVersion": 2,
	  "packages": {
	    "": {"version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.11"}
	  },
	  "dependencies": {
	    "lodash": {"version": "4.17.10"}
	  }
	}`)
	pkgs, _, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1 (from \"packages\" only, not one from each): %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Version != "4.17.11" {
		t.Errorf("Version = %q, want 4.17.11 - \"packages\" is the canonical shape "+
			"and must win over the legacy \"dependencies\" tree", pkgs[0].Version)
	}
}

// A malformed lockfile is an error, not an empty result. "Zero packages"
// renders as a clean scan; an error exits 2.
func TestParse_MalformedJSONIsAnErrorNotAnEmptyResult(t *testing.T) {
	p := write(t, `{"lockfileVersion": 3, "packages": `)
	_, _, err := Parse(p)
	if err == nil {
		t.Fatal("Parse returned nil error on truncated JSON — an unreadable " +
			"lockfile must not read as a clean scan")
	}
	// Asserted on the full PATH, not the bare filename. A wrapper such as
	// fmt.Errorf("parse package-lock.json: %w", err) satisfies a check for
	// "package-lock.json" from its own hard-coded prefix even after dropping
	// both the path and the cause - the exact defect CLAUDE.md records.
	if !strings.Contains(err.Error(), p) {
		t.Errorf("error %q does not name the file it failed on (%s)", err, p)
	}
}

// A directory scan may find a manifest entry for a lockfile that turns out
// not to exist (e.g. gitignored, or removed since the walk), and the error
// still has to say which of possibly many lockfiles it was - gomod covers
// the equivalent case for go.mod.
func TestParse_MissingFileNamesThePath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "package-lock.json") // never written
	_, _, err := Parse(p)
	if err == nil {
		t.Fatal("Parse returned nil error for a lockfile that does not exist")
	}
	// Unlike the malformed-JSON check above, wrapping this specific error with
	// %w behind a hard-coded "package-lock.json" prefix would NOT be caught by
	// this assertion: %w's formatting includes the wrapped error's own text,
	// and os.ReadFile's error already names the full path ("open <path>: ...")
	// on its own, so the path survives even through a wrapper whose own
	// literal text never mentions it. Verified directly (task-2-report.md,
	// Fix round 1, Minor 4) - that mutation passed, and correctly so; only a
	// wrapper that also drops the underlying cause (%v of a fabricated string,
	// not %w of err) defeats this check, which is what the code below actually
	// does by returning err unwrapped.
	if !strings.Contains(err.Error(), p) {
		t.Errorf("error %q does not name the missing path %s", err, p)
	}
}
