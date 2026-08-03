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
	if stats.Components != 4 {
		t.Errorf("Components = %d, want 4 — every entry is seen, including the "+
			"three that cannot be matched", stats.Components)
	}
	if stats.SkippedNoVersion != 3 {
		t.Errorf("SkippedNoVersion = %d, want 3 (root, link, no-version)",
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
