package dirscan

import (
	"fmt"
	"testing"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
)

// The measurement D26 records, as a test. A directory holding go.mod and
// package-lock.json must catalog BOTH ecosystems, and name requirements.txt
// as unread.
func TestParse_CatalogsEveryLockfileAndNamesTheRest(t *testing.T) {
	root := mkdir(t, map[string]string{
		"go.mod": "module example.com/poly\n\ngo 1.22\n\n" +
			"require gopkg.in/yaml.v2 v2.2.1\n",
		"package-lock.json": `{"lockfileVersion":3,"packages":{` +
			`"":{"version":"1.0.0"},` +
			`"node_modules/lodash":{"version":"4.17.11"}}}`,
		"requirements.txt": "Django==3.2.12\n",
	})
	target, stats, unread, err := Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	byEco := map[string]int{}
	for _, p := range target.Packages {
		byEco[p.Ecosystem]++
	}
	if byEco["Go"] == 0 || byEco["npm"] == 0 {
		t.Errorf("ecosystems = %v, want both Go and npm — cataloging only one is "+
			"the defect D26 records", byEco)
	}
	if stats.Components != stats.Cataloged+stats.SkippedNoPURL+
		stats.SkippedNoVersion+stats.SkippedUnsupportedEcosystem {
		t.Errorf("the invariant does not survive the merge: %+v", stats)
	}
	if len(unread) != 1 || unread[0].Path != "requirements.txt" {
		t.Fatalf("unread = %+v, want exactly requirements.txt", unread)
	}
	if unread[0].Reason == "" {
		t.Error("the unread entry carries no reason — a reader told only that " +
			"something was skipped cannot act on it")
	}
}

// The merge invariant check above (Components == Cataloged + skips) is
// satisfied even if the merged Stats is overwritten by the LAST manifest
// processed rather than summed across all of them: each per-manifest
// cataloger already guarantees that invariant on its own, so whichever one
// runs last still passes it by itself. Only comparing the merged totals
// against a value computed by hand — not just checking internal
// self-consistency — tells overwriting apart from summing.
func TestParse_StatsAreSummedNotOverwritten(t *testing.T) {
	root := mkdir(t, map[string]string{
		"go.mod": "module example.com/sum\n\ngo 1.22\n\n" +
			"require gopkg.in/yaml.v2 v2.2.1\n",
		"package-lock.json": `{"lockfileVersion":3,"packages":{` +
			`"":{"version":"1.0.0"},` +
			`"node_modules/lodash":{"version":"4.17.11"}}}`,
	})
	_, stats, _, err := Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	// go.mod's one require line contributes Components=1, Cataloged=1.
	// package-lock.json's two entries ("" root, skipped with no version, and
	// lodash, cataloged) contribute Components=2, Cataloged=1,
	// SkippedNoVersion=1. Summed: Components=3, Cataloged=2,
	// SkippedNoVersion=1 — a total neither manifest's own Stats holds alone,
	// so only summing (not overwriting) can produce it.
	want := cyclonedx.Stats{Components: 3, Cataloged: 2, SkippedNoVersion: 1}
	if stats != want {
		t.Errorf("stats = %+v, want %+v — merging must sum every manifest's "+
			"Stats, not keep only the last one processed", stats, want)
	}
}

// One unreadable manifest must not take the others down with it, and must not
// vanish: "we looked and could not read it" is a different fact from "we did
// not look", and both belong in the report.
func TestParse_AnUnparseableManifestBecomesUnreadNotAnAbort(t *testing.T) {
	root := mkdir(t, map[string]string{
		"package-lock.json":        `{"lockfileVersion":3,"packages":{"":{"version":"1"},"node_modules/ok":{"version":"1.0.0"}}}`,
		"broken/package-lock.json": `{"lockfileVersion":3, `,
	})
	target, _, unread, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse = %v; one bad manifest must not abandon the scan", err)
	}
	if len(target.Packages) == 0 {
		t.Error("the readable lockfile's packages were lost")
	}
	var found bool
	for _, u := range unread {
		if u.Path == "broken/package-lock.json" {
			found = true
			if u.Reason == "" {
				t.Error("the failed manifest carries no reason")
			}
		}
	}
	if !found {
		t.Errorf("unread = %+v, want it to name broken/package-lock.json", unread)
	}
}

// Deterministic across runs: same tree, same bytes.
func TestParse_PackageOrderIsDeterministic(t *testing.T) {
	files := map[string]string{
		"z/package-lock.json": `{"lockfileVersion":3,"packages":{"":{"version":"1"},"node_modules/zzz":{"version":"1.0.0"}}}`,
		"a/package-lock.json": `{"lockfileVersion":3,"packages":{"":{"version":"1"},"node_modules/aaa":{"version":"1.0.0"}}}`,
	}
	first, _, _, err := Parse(mkdir(t, files))
	if err != nil {
		t.Fatal(err)
	}
	second, _, _, err := Parse(mkdir(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(first.Packages) != fmt.Sprint(second.Packages) {
		t.Errorf("two scans of the same tree differ:\n  %v\n  %v",
			first.Packages, second.Packages)
	}
}

// The determinism test above passes even if the merge omits the sort
// entirely: Walk's manifest order is already deterministic (sorted by
// path), and each per-manifest parser is deterministic given fixed file
// content, so two runs of an identical tree agree with EACH OTHER regardless
// of whether an explicit merge-time sort ever runs. This fixture is chosen
// so walk order and name order disagree — "a/..." (containing zzz) is
// walked BEFORE "b/..." (containing aaa) even though aaa sorts before zzz —
// so only an actual sort by name produces the order asserted below; the
// natural append order would produce [zzz, aaa] instead.
func TestParse_PackagesAreSortedByNameNotWalkOrder(t *testing.T) {
	root := mkdir(t, map[string]string{
		"a/package-lock.json": `{"lockfileVersion":3,"packages":{"":{"version":"1"},"node_modules/zzz":{"version":"1.0.0"}}}`,
		"b/package-lock.json": `{"lockfileVersion":3,"packages":{"":{"version":"1"},"node_modules/aaa":{"version":"1.0.0"}}}`,
	})
	target, _, _, err := Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 2 {
		t.Fatalf("packages = %v, want 2", target.Packages)
	}
	if target.Packages[0].Name != "aaa" || target.Packages[1].Name != "zzz" {
		t.Errorf("order = [%s, %s], want [aaa, zzz] — the merge must sort by "+
			"name, not just append in the order Walk visited manifests",
			target.Packages[0].Name, target.Packages[1].Name)
	}
}

// A directory with no recognized manifest at all is an error, the way
// gomod.Parse already errors on a missing go.mod — not an empty clean scan.
func TestParse_NoManifestsAtAllIsAnError(t *testing.T) {
	root := mkdir(t, map[string]string{"README.md": "# nothing here\n"})
	_, _, _, err := Parse(root)
	if err == nil {
		t.Fatal("Parse returned nil error for a directory with no manifests — " +
			"that must not read as a clean scan of zero packages")
	}
}
