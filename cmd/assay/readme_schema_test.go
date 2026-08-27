package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/dbcmd"
	"github.com/kun9497/assay/internal/store"
)

// docCacheDirPattern finds the schema-versioned cache directory as it is
// quoted in prose, on both path separators: the Windows row spells it
// `assay\db\v6\`, macOS and Linux spell it `assay/db/v6/`.
var docCacheDirPattern = regexp.MustCompile(`assay[/\\]db[/\\]v(\d+)[/\\]`)

// srcArtifactTagPattern finds a schema-versioned artifact tag written as a
// literal in Go source: `ghcr.io/kun9497/assay-db:v6`, or any other
// registry path carrying a `:vN` tag.
var srcArtifactTagPattern = regexp.MustCompile(`[\w.\-]+/[\w.\-/]+:v(\d+)`)

// docsClaimingTheCacheDir are every file that states, as a claim about where
// the database currently lives, the schema-versioned cache directory:
// README's own Location table and prose, and the roadmap's -- which repeats
// the same fact in its "D5" decision, its storage-layout diagram, and its
// own Location table, because the roadmap is written as a reference design
// a reader consults independently of the README, not merely a link to it.
//
// The roadmap's OCI-artifact tag mention ("Ref renders it as :v7", D28) and
// README's own "assay db push ghcr.io/kun9497/assay-db:v7" example carry the
// same number but a different shape (":vN", not "assay/db/vN/") and are
// fixed by hand alongside everything else in this file, but deliberately not
// matched here -- see the doc comment below on why this guard stays narrow.
var docsClaimingTheCacheDir = []string{
	// The cache-directory table lived in README until 2026-08-27, when the
	// README became a lean landing page and the design/reference content
	// moved to docs/DESIGN.md. These are the files that still state where the
	// versioned cache lives, so a schema bump has to touch each one.
	"docs/DESIGN.md",
	"docs/DESIGN.ko.md",
	"docs/superpowers/specs/2026-07-29-assay-roadmap.md",
	"docs/superpowers/specs/2026-07-29-assay-roadmap.ko.md",
}

// findRepoRoot walks up from the test's own working directory (cmd/assay,
// under `go test`) looking for go.mod, rather than hardcoding a path that
// would silently stop working the moment this package or the repo moved.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("findRepoRoot: os.Getwd: %v", err)
	}
	start := dir
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("findRepoRoot: no go.mod found walking up from %s", start)
		}
		dir = parent
	}
}

// TestDocs_CacheDirMatchesSchemaVersion holds a guarantee neither test nor
// review has held twice now: that every "assay/db/vN/" cache path quoted in
// README or the roadmap names the CURRENT schema, not whatever it was when
// that paragraph was last written. v5 stayed in the prose after a bump to
// v6, uncaught until someone went looking; v6 did the same across a bump to
// v7, in both places -- the roadmap's own Location table and storage-layout
// diagram drifted right along with README's.
//
// This was named TestREADME_... until the roadmap's copies of the same
// claim turned out to need the same guard, which is worth recording here so
// the rename reads as deliberate rather than as churn.
//
// A pin on a literal number would only need updating at the same moment the
// prose does, and by the same person who forgets the prose -- so this reads
// store.SchemaVersion directly, the way internal/provider/osv/record_test.go
// duplicates the same constant as a second, independent assertion (there to
// pin the value; here to pin the documentation against it) so drift is
// caught without anyone having to remember to run a grep.
func TestDocs_CacheDirMatchesSchemaVersion(t *testing.T) {
	root := findRepoRoot(t)
	for _, name := range docsClaimingTheCacheDir {
		name := name
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, filepath.FromSlash(name))
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			matches := docCacheDirPattern.FindAllStringSubmatch(string(data), -1)
			if len(matches) == 0 {
				t.Fatalf("%s: found no \"assay/db/vN/\" cache path at all -- "+
					"either the file stopped documenting the cache directory, or "+
					"the pattern this test looks for no longer matches how it is "+
					"written there, and either way this guard would otherwise pass "+
					"on a file that says nothing", name)
			}
			for _, m := range matches {
				found, err := strconv.Atoi(m[1])
				if err != nil {
					t.Fatalf("%s: cache path version %q did not parse as a number: %v",
						name, m[1], err)
				}
				if found != store.SchemaVersion {
					t.Errorf("%s: documents the cache directory as v%d, but "+
						"store.SchemaVersion is v%d -- update every v%d in %s to v%d",
						name, found, store.SchemaVersion, found, name, store.SchemaVersion)
				}
			}
		})
	}
}

// TestSource_CLIMessagesDeriveTheArtifactTag holds the same guarantee one
// layer down from the documentation: the tag `cmd/assay` SHOWS a user is
// derived from store.SchemaVersion, not typed.
//
// The sibling above exists because "assay/db/vN/" drifted in prose twice.
// It drifted in code as well, and nothing caught it: three error messages —
// `--from`, `--seed`, and `db push` — still named `:v6` after the bump to
// v7, so `db update`'s own instructions pointed at a tag that 404s, and
// `db push`'s pointed a PUBLISHER at the wrong tag entirely. Everything else
// in the package already went through dbcmd.Ref; these three were the
// literals it never reached.
//
// Two assertions, because either alone is weak. The first is behavioural: it
// drives each message and requires the CURRENT tag in it, so a literal that
// happens to be right today fails the moment SchemaVersion moves. The second
// scans the source for any literal at all, which catches the case the first
// cannot — a fourth message added later, in a branch no test drives.
func TestSource_CLIMessagesDeriveTheArtifactTag(t *testing.T) {
	want := dbcmd.Ref(dbcmd.DefaultRef)
	// Guarded rather than assumed: if Ref ever stopped putting the schema in
	// the tag, every assertion below would still pass while the thing being
	// held stopped being true.
	if !strings.HasSuffix(want, ":v"+strconv.Itoa(store.SchemaVersion)) {
		t.Fatalf("dbcmd.Ref(DefaultRef) = %q, which does not end in the current schema tag :v%d -- "+
			"this test's oracle is no longer the thing it is meant to hold", want, store.SchemaVersion)
	}

	t.Run("the messages name it", func(t *testing.T) {
		// Each case is an argument shape whose rejection SUGGESTS a reference,
		// which is the only place a tag is shown to a user.
		for _, tc := range []struct {
			name string
			run  func(stderr *bytes.Buffer)
		}{
			{"db update --from with no value", func(stderr *bytes.Buffer) {
				resolveUpdateRef([]string{"db", "update", "--from"}, stderr)
			}},
			{"db build --seed with no value", func(stderr *bytes.Buffer) {
				resolveBuildSeed([]string{"db", "build", "--seed"}, stderr)
			}},
			{"db push with no reference", func(stderr *bytes.Buffer) {
				resolvePushRef([]string{"db", "push"}, stderr)
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var stderr bytes.Buffer
				tc.run(&stderr)
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("%s suggests a reference that is not the current one (%s):\n%s",
						tc.name, want, stderr.String())
				}
			})
		}
	})

	t.Run("and no source file spells one out", func(t *testing.T) {
		// The pattern is checked against a known-positive control first. A
		// source scan that finds nothing is the PASSING state here -- the
		// opposite of the documentation guard above, where finding nothing
		// means the prose stopped saying it -- so a pattern that silently
		// stopped matching would leave this assertion green forever.
		const control = "ghcr.io/kun9497/assay-db:v6"
		if m := srcArtifactTagPattern.FindStringSubmatch(control); m == nil || m[1] != "6" {
			t.Fatalf("srcArtifactTagPattern no longer matches %q (%v), so scanning with it proves nothing",
				control, m)
		}

		dir := filepath.Join(findRepoRoot(t), "cmd", "assay")
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		// Non-test files only. A _test.go file naming "example.test/mirror:v6"
		// is using an arbitrary reference as INPUT -- it makes no claim about
		// where the real artifact lives, and rewriting those on every schema
		// bump would be churn that teaches people to ignore this test.
		scanned := 0
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			scanned++
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range srcArtifactTagPattern.FindAllStringSubmatch(string(data), -1) {
				t.Errorf("cmd/assay/%s contains the literal artifact tag %q -- write "+
					"dbcmd.Ref(dbcmd.DefaultRef) instead, so it follows store.SchemaVersion (now v%d) "+
					"rather than drifting the way :v6 did across the bump to v7",
					name, m[0], store.SchemaVersion)
			}
		}
		if scanned == 0 {
			t.Fatal("scanned no non-test Go file in cmd/assay, so this guard held nothing")
		}
	})
}
