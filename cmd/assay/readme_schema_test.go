package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/kun9497/assay/internal/store"
)

// readmeCacheDirPattern finds the schema-versioned cache directory as it is
// quoted in prose, on both path separators: the Windows row spells it
// `assay\db\v6\`, macOS and Linux spell it `assay/db/v6/`.
var readmeCacheDirPattern = regexp.MustCompile(`assay[/\\]db[/\\]v(\d+)[/\\]`)

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

// TestREADME_CacheDirMatchesSchemaVersion holds a guarantee neither test nor
// review has held twice now: that every "assay/db/vN/" cache path quoted in
// either README names the CURRENT schema, not whatever it was when that
// paragraph was last written. v5 stayed in the prose after a bump to v6,
// uncaught until someone went looking; v6 did the same across a bump to v7.
// A pin on a literal number would only need updating at the same moment the
// prose does, and by the same person who forgets the prose -- so this reads
// store.SchemaVersion directly, the way internal/provider/osv/record_test.go
// duplicates the same constant as a second, independent assertion (there to
// pin the value; here to pin the README against it) so drift is caught
// without anyone having to remember to run a grep.
func TestREADME_CacheDirMatchesSchemaVersion(t *testing.T) {
	root := findRepoRoot(t)
	for _, name := range []string{"README.md", "README.ko.md"} {
		name := name
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			matches := readmeCacheDirPattern.FindAllStringSubmatch(string(data), -1)
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
