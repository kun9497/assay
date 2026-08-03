package dirscan

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// The measurement D26 records, as a test. A directory holding go.mod and
// package-lock.json must catalog BOTH ecosystems, and name requirements.txt
// as mf.Unread.
func TestParse_CatalogsEveryLockfileAndNamesTheRest(t *testing.T) {
	root := mkdir(t, map[string]string{
		"go.mod": "module example.com/poly\n\ngo 1.22\n\n" +
			"require gopkg.in/yaml.v2 v2.2.1\n",
		"package-lock.json": `{"lockfileVersion":3,"packages":{` +
			`"":{"version":"1.0.0"},` +
			`"node_modules/lodash":{"version":"4.17.11"}}}`,
		"requirements.txt": "Django==3.2.12\n",
	})
	target, stats, mf, err := Parse(root)
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
	if len(mf.Unread) != 1 || mf.Unread[0].Path != "requirements.txt" {
		t.Fatalf("mf.Unread = %+v, want exactly requirements.txt", mf.Unread)
	}
	if mf.Unread[0].Reason == "" {
		t.Error("the mf.Unread entry carries no reason — a reader told only that " +
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

// One mf.Unreadable manifest must not take the others down with it, and must not
// vanish: "we looked and could not read it" is a different fact from "we did
// not look", and both belong in the report.
func TestParse_AnUnparseableManifestBecomesUnreadNotAnAbort(t *testing.T) {
	root := mkdir(t, map[string]string{
		"package-lock.json":        `{"lockfileVersion":3,"packages":{"":{"version":"1"},"node_modules/ok":{"version":"1.0.0"}}}`,
		"broken/package-lock.json": `{"lockfileVersion":3, `,
	})
	target, _, mf, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse = %v; one bad manifest must not abandon the scan", err)
	}
	if len(target.Packages) == 0 {
		t.Error("the readable lockfile's packages were lost")
	}
	var found bool
	for _, u := range mf.Unread {
		if u.Path == "broken/package-lock.json" {
			found = true
			if u.Reason == "" {
				t.Error("the failed manifest carries no reason")
			}
		}
	}
	if !found {
		t.Errorf("mf.Unread = %+v, want it to name broken/package-lock.json", mf.Unread)
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

// --- Fix round 1 (code review) ---

// relocate's own comment explains why it rewrites Location.Path, but nothing
// before this test asserted the value it writes — only that two runs agree
// with each other (TestParse_PackageOrderIsDeterministic) or that a value is
// present (TestParse_CatalogsEveryLockfileAndNamesTheRest's mf.Unread checks,
// which do not touch Locations at all). Changing relocate's assignment to
// `= ""` would still pass every test above; this is the one that would not.
func TestParse_LocationIsTheManifestsOwnRelativePath(t *testing.T) {
	root := mkdir(t, map[string]string{
		"frontend/package-lock.json": `{"lockfileVersion":3,"packages":{` +
			`"":{"version":"1"},"node_modules/lodash":{"version":"4.17.11"}}}`,
	})
	target, _, _, err := Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("packages = %v, want exactly 1", target.Packages)
	}
	p := target.Packages[0]
	if len(p.Locations) != 1 || p.Locations[0].Path != "frontend/package-lock.json" {
		t.Errorf("Locations = %+v, want exactly one entry naming %q",
			p.Locations, "frontend/package-lock.json")
	}
}

// gomod.Parse builds its own Location.Path from filepath.Dir(full) joined
// back with "go.mod" internally — a different construction from npmlock's
// and poetrylock's (they use the path they were handed directly) — so it
// gets its own test rather than trusting the npm case above to cover it.
func TestParse_GoModLocationIsAlsoTheManifestsOwnRelativePath(t *testing.T) {
	root := mkdir(t, map[string]string{
		"backend/go.mod": "module example.com/backend\n\ngo 1.22\n\n" +
			"require gopkg.in/yaml.v2 v2.2.1\n",
	})
	target, _, _, err := Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("packages = %v, want exactly 1", target.Packages)
	}
	p := target.Packages[0]
	if len(p.Locations) != 1 || p.Locations[0].Path != "backend/go.mod" {
		t.Errorf("Locations = %+v, want exactly one entry naming %q",
			p.Locations, "backend/go.mod")
	}
}

// walk.go's Kind enum and parseManifest's switch are two separate
// declarations kept in sync only by hand. Constructing a Manifest with a
// Kind neither Walk nor this test needs to define — Kind is just a string —
// exercises the switch's default branch directly, without touching walk.go.
func TestParse_UnhandledKindBecomesUnreadNotSilent(t *testing.T) {
	m := Manifest{Path: "mystery.lock", Kind: Kind("mystery-manifest")}
	pkgs, stats, u := parseManifest("irrelevant-root", m)
	if pkgs != nil {
		t.Errorf("packages = %v, want nil for a Kind with no parser", pkgs)
	}
	if stats != (cyclonedx.Stats{}) {
		t.Errorf("stats = %+v, want the zero value for a Kind with no parser", stats)
	}
	if u == nil {
		t.Fatal("Unread = nil — a Kind this switch has no case for must not " +
			"vanish silently (no packages, no Unread, no error)")
	}
	if u.Path != "mystery.lock" {
		t.Errorf("Path = %q, want %q", u.Path, "mystery.lock")
	}
	if u.Reason == "" {
		t.Error("Reason is empty — an unhandled Kind must say why it was not read")
	}
}

// Only Reason != "" was asserted anywhere above, which a single shared
// string across every Unread entry would satisfy just as well. This checks
// that a parse failure's Reason actually carries the underlying error text
// (not a generic placeholder) and that it is a different string from
// requirements.txt's fixed reason — collapsing both into one flattened
// explanation would pass every earlier assertion.
func TestParse_UnreadReasonIsNotFlattenedToOneSharedString(t *testing.T) {
	root := mkdir(t, map[string]string{
		"broken/package-lock.json": `{"lockfileVersion":3, `,
		"requirements.txt":         "Django==3.2.12\n",
	})
	_, _, mf, err := Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	var brokenReason, reqReason string
	for _, u := range mf.Unread {
		switch u.Path {
		case "broken/package-lock.json":
			brokenReason = u.Reason
		case "requirements.txt":
			reqReason = u.Reason
		}
	}
	if brokenReason == "" || reqReason == "" {
		t.Fatalf("mf.Unread = %+v, want entries for both broken/package-lock.json "+
			"and requirements.txt", mf.Unread)
	}
	if !strings.Contains(brokenReason, "unexpected end of JSON input") {
		t.Errorf("broken reason = %q, want it to contain the underlying JSON "+
			"decode error", brokenReason)
	}
	if brokenReason == reqReason {
		t.Errorf("both reasons are %q — a parse failure and a deliberately "+
			"mf.Unread file must not share one flattened explanation", brokenReason)
	}
}

// D7: a directory is not an operating system. Every other test above
// happens to leave Distro untouched, but none of them ever look at it — this
// is the one that would fail if a future change ever set it.
func TestParse_DistroStaysEmpty(t *testing.T) {
	root := mkdir(t, map[string]string{
		"go.mod": "module example.com/nodistro\n\ngo 1.22\n\n" +
			"require gopkg.in/yaml.v2 v2.2.1\n",
	})
	target, _, _, err := Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	if target.Distro != nil {
		t.Errorf("Distro = %+v, want nil — a directory is not an operating "+
			"system (D7)", target.Distro)
	}
}

// TestParse_PackagesAreSortedByNameNotWalkOrder only forces the Name key.
// sort.Slice gives no guarantee about the relative order of two elements a
// comparator calls equal (that is what sort.SliceStable is for), so a
// comparator missing the Ecosystem, Version, or Location key would not
// necessarily fail loud through Parse's end-to-end fixtures — ties could
// just as easily land in the "right" place by luck of the algorithm. Testing
// lessPackage directly, with every higher key tied and only the key under
// test differing (and every LOWER key deliberately disagreeing, so a
// comparator that skipped straight to it would get the wrong answer), pins
// down that all four keys actually participate.
func TestLessPackage_EachKeyDecidesWhenEarlierKeysTie(t *testing.T) {
	pkg := func(eco, name, version, loc string) pkgmeta.Package {
		return pkgmeta.Package{
			Ecosystem: eco,
			Name:      name,
			Version:   version,
			Locations: []pkgmeta.Location{{Path: loc}},
		}
	}
	cases := []struct {
		name string
		a, b pkgmeta.Package
	}{
		{
			// Name, Version and Location all disagree in the OPPOSITE
			// direction from what "a before b" requires — only Ecosystem
			// being consulted first makes this pass.
			name: "ecosystem",
			a:    pkg("Go", "zzz", "9", "z"),
			b:    pkg("npm", "aaa", "1", "a"),
		},
		{
			name: "name",
			a:    pkg("Go", "aaa", "9", "z"),
			b:    pkg("Go", "zzz", "1", "a"),
		},
		{
			name: "version",
			a:    pkg("Go", "aaa", "1.0.0", "z"),
			b:    pkg("Go", "aaa", "2.0.0", "a"),
		},
		{
			name: "location",
			a:    pkg("Go", "aaa", "1.0.0", "a"),
			b:    pkg("Go", "aaa", "1.0.0", "z"),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !lessPackage(c.a, c.b) {
				t.Errorf("lessPackage(a, b) = false, want true — %s must decide "+
					"this pair once every earlier key has tied", c.name)
			}
			if lessPackage(c.b, c.a) {
				t.Errorf("lessPackage(b, a) = true, want false — the order must " +
					"be strict, not true in both directions")
			}
		})
	}
}

// The disclosure D23 prints is about go.mod SPECIFICALLY — it names what the
// module requires, not what a build links — so it needs go.mod's own count,
// not the merged total. Stating it with the total would attribute every
// lockfile's packages to go.mod, and a caveat carrying the wrong number is
// worse than no caveat, because it reads as precise.
//
// The fixture gives the two manifests DIFFERENT counts on purpose: with both
// at one, a disclosure reading the merged total would still print the right
// number here and the test would pass on a bug.
func TestParse_ReadRecordsEachManifestsOwnComponentCount(t *testing.T) {
	root := mkdir(t, map[string]string{
		"go.mod": "module example.com/poly\n\ngo 1.22\n\n" +
			"require (\n\tgopkg.in/yaml.v2 v2.2.1\n\texample.com/other v1.0.0\n)\n",
		"package-lock.json": `{"lockfileVersion":3,"packages":{` +
			`"":{"version":"1.0.0"},"node_modules/lodash":{"version":"4.17.11"}}}`,
	})
	_, stats, mf, err := Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	gomod, ok := mf.GoMod()
	if !ok {
		t.Fatal("GoMod() reported no go.mod in a directory that has one")
	}
	if gomod.Components != 2 {
		t.Errorf("go.mod Components = %d, want 2 — its own count, not the merged %d",
			gomod.Components, stats.Components)
	}
	if gomod.Components == stats.Components {
		t.Errorf("go.mod's count equals the merged total (%d), so this fixture "+
			"cannot tell the two apart", stats.Components)
	}
	if gomod.Path != "go.mod" {
		t.Errorf("go.mod Path = %q, want %q", gomod.Path, "go.mod")
	}
}

// ...and a directory with no go.mod must say so, because the D23 caveat must
// not be printed for a Python-only or JavaScript-only project.
func TestParse_GoModReportsAbsenceRatherThanAZeroValue(t *testing.T) {
	root := mkdir(t, map[string]string{
		"package-lock.json": `{"lockfileVersion":3,"packages":{` +
			`"":{"version":"1.0.0"},"node_modules/lodash":{"version":"4.17.11"}}}`,
	})
	_, _, mf, err := Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mf.GoMod(); ok {
		t.Error("GoMod() claimed a go.mod in a directory that has none")
	}
}
