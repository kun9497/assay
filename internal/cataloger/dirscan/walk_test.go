package dirscan

import (
	"os"
	"path/filepath"
	"testing"
)

// mkdir builds a tree from a path -> contents map. Directories are implied by
// the paths, so a test reads as the shape it is describing.
func mkdir(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func paths(ms []Manifest) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Path)
	}
	return out
}

// The shape the whole slice exists for: manifests in subdirectories are found.
// Reading only the root reproduces the defect one level down, in a repository
// layout that is completely ordinary.
func TestWalk_FindsManifestsInSubdirectories(t *testing.T) {
	root := mkdir(t, map[string]string{
		"go.mod":                        "module example.com/x\n",
		"frontend/package-lock.json":    "{}",
		"services/api/poetry.lock":      "",
		"services/api/requirements.txt": "",
	})
	got, _, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"frontend/package-lock.json",
		"go.mod",
		"services/api/poetry.lock",
		"services/api/requirements.txt",
	}
	if len(got) != len(want) {
		t.Fatalf("found %v, want %v", paths(got), want)
	}
	for i := range want {
		if got[i].Path != want[i] {
			t.Errorf("result[%d] = %q, want %q (results must be sorted by path)",
				i, got[i].Path, want[i])
		}
	}
}

// Sorted, so two runs over one tree cannot differ. This is NOT provable by
// any fixture whose WalkDir traversal order already equals its sorted order —
// filepath.WalkDir is depth-first, not lexical-by-full-path, and those two
// orders usually coincide but are not the same thing. "a" and "a-b" are the
// smallest pair that tells them apart: '-' (0x2D) sorts before '/' (0x2F), so
// "a-b/..." sorts before "a/..." lexically, but WalkDir visits root entry "a"
// first and walks it to completion - including its file - before it ever
// reaches sibling "a-b". Only a fixture like this one fails if the explicit
// sort is removed.
func TestWalk_ResultsAreSorted(t *testing.T) {
	root := mkdir(t, map[string]string{
		"a/package-lock.json":   "{}",
		"a-b/package-lock.json": "{}",
	})
	got, _, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a-b/package-lock.json", "a/package-lock.json"}
	for i := range want {
		if got[i].Path != want[i] {
			t.Fatalf("order = %v, want %v", paths(got), want)
		}
	}
}

// A lockfile inside a dependency tree describes that dependency's own
// requirements, not this project's — and node_modules alone can hold tens of
// thousands. Each excluded directory is asserted separately: a single fixture
// with all three passes even if only one exclusion is implemented.
func TestWalk_SkipsDependencyAndVCSDirectories(t *testing.T) {
	for _, dir := range []string{"node_modules", "vendor", ".git"} {
		t.Run(dir, func(t *testing.T) {
			root := mkdir(t, map[string]string{
				"package-lock.json":            "{}",
				dir + "/dep/package-lock.json": "{}",
			})
			got, unread, err := Walk(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Path != "package-lock.json" {
				t.Errorf("found %v, want only the root manifest — %s must not be "+
					"descended into", paths(got), dir)
			}
			// A prune is a DECISION, not a failure, and the two must not reach
			// the exit code as the same thing. Walk records what it could not
			// read; node_modules is something it chose not to read, and every
			// repository with dependencies installed has one - reporting it
			// would fail --fail-on-incomplete on essentially every scan.
			if len(unread) != 0 {
				t.Errorf("unread = %+v, want none — skipping %s is a decision, not a "+
					"coverage failure", unread, dir)
			}
		})
	}
}

// Depth is capped so nesting cannot make a scan arbitrarily slow. The cap is
// asserted at its exact boundary in both directions: a fixture only past the
// limit would pass with an off-by-one cap.
func TestWalk_DepthIsCappedAtItsBoundary(t *testing.T) {
	atLimit := "a/b/c/d/e/f/package-lock.json"     // 6 directories deep
	pastLimit := "a/b/c/d/e/f/g/package-lock.json" // 7 — one too far
	root := mkdir(t, map[string]string{atLimit: "{}", pastLimit: "{}"})
	got, unread, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != atLimit {
		t.Errorf("found %v, want exactly %q — the cap must admit its own limit "+
			"and exclude one past it", paths(got), atLimit)
	}
	// The depth cap is the same kind of decision as excludedDirs: a bounded
	// walk, not a walk that hit something it could not read. Emitting an unread
	// entry here would make every deeply nested repository report incomplete
	// coverage it does not have.
	if len(unread) != 0 {
		t.Errorf("unread = %+v, want none — the depth cap is a decision, not a "+
			"coverage failure", unread)
	}
}

// Recognized but never read (D26). It must appear in the walk so the
// disclosure can name it; Task 2 is what refuses to parse it.
func TestWalk_RecognizesRequirementsTxtWithoutTreatingItAsALockfile(t *testing.T) {
	root := mkdir(t, map[string]string{"requirements.txt": "Django==3.2.12\n"})
	got, _, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("found %v, want 1", paths(got))
	}
	if got[0].Kind != KindRequirements {
		t.Errorf("Kind = %q, want %q", got[0].Kind, KindRequirements)
	}
}

// A file whose NAME contains a manifest name is not that manifest.
// "package-lock.json.bak" and "my-go.mod" are not manifests, and a
// suffix/prefix match would claim they are.
func TestWalk_MatchesTheWholeFilenameNotASubstring(t *testing.T) {
	root := mkdir(t, map[string]string{
		"package-lock.json.bak": "{}",
		"my-go.mod":             "",
		"go.mod.orig":           "",
	})
	got, _, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("found %v, want none — these are not manifests", paths(got))
	}
}

// A directory that cannot be read is a fact about coverage, not a reason to
// abandon the scan: the rest of the tree is still worth reporting. It must not
// silently vanish either — every manifest inside it is invisible to the walk,
// so the only trace it can leave is the unread entry asserted here.
//
// This test used to skip on Windows and assert only that the walk continued,
// with a comment saying the unread list was a later task's job. It is that
// task's test now: makeUnreadable stages the hazard on both platforms (an
// exclusive handle on Windows, mode 0o000 elsewhere), so there is one test of
// this behaviour rather than one that runs and one that documents.
func TestWalk_AnUnreadableSubdirectoryIsReportedAndDoesNotAbortTheWalk(t *testing.T) {
	root := mkdir(t, map[string]string{
		"package-lock.json":     "{}",
		"sub/package-lock.json": "{}",
	})
	sub := filepath.Join(root, "sub")
	makeUnreadable(t, sub)
	// Verified, not assumed: if this environment can still enumerate the
	// directory, the fixture does not stage the hazard and the test must say so
	// rather than report a pass it did not earn.
	if _, err := os.ReadDir(sub); err == nil {
		t.Skip("os.ReadDir still succeeds on the locked directory; this environment cannot stage the hazard")
	}

	got, unread, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk returned %v; an unreadable subdirectory must not abort the walk", err)
	}
	// The walk continued: the readable sibling manifest is still here. Without
	// this, a Walk that gave up at the first error would pass every assertion
	// below.
	if len(got) != 1 || got[0].Path != "package-lock.json" {
		t.Errorf("manifests = %v, want the readable root manifest — the walk must "+
			"continue past a subtree it could not enter", paths(got))
	}
	if len(unread) != 1 {
		t.Fatalf("unread = %+v, want exactly one entry for %q", unread, "sub")
	}
	if unread[0].Path != "sub" {
		t.Errorf("unread[0].Path = %q, want %q (root-relative, forward-slashed)",
			unread[0].Path, "sub")
	}
	// Failed is what AnyFailed() reads and what --fail-on-incomplete gates on.
	// An entry that is merely listed changes nothing about the exit code, which
	// is the half of this defect that let a scan of an unreadable tree exit 0.
	if !unread[0].Failed {
		t.Errorf("unread[0].Failed = false, want true — a subtree that could not be " +
			"read is coverage this scan cannot stand behind, not a decision")
	}
	// The reason has to travel with it: "sub was skipped" is not something a
	// reader can act on without knowing why.
	if unread[0].Reason == "" {
		t.Error("unread[0].Reason is empty; the disclosure would name a directory and no cause")
	}
}
