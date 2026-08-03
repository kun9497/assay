package dirscan

import (
	"os"
	"path/filepath"
	"runtime"
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
	got, err := Walk(root)
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
	got, err := Walk(root)
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
			got, err := Walk(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Path != "package-lock.json" {
				t.Errorf("found %v, want only the root manifest — %s must not be "+
					"descended into", paths(got), dir)
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
	got, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != atLimit {
		t.Errorf("found %v, want exactly %q — the cap must admit its own limit "+
			"and exclude one past it", paths(got), atLimit)
	}
}

// Recognized but never read (D26). It must appear in the walk so the
// disclosure can name it; Task 2 is what refuses to parse it.
func TestWalk_RecognizesRequirementsTxtWithoutTreatingItAsALockfile(t *testing.T) {
	root := mkdir(t, map[string]string{"requirements.txt": "Django==3.2.12\n"})
	got, err := Walk(root)
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
	got, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("found %v, want none — these are not manifests", paths(got))
	}
}

// A directory that cannot be read is a fact about coverage, not a reason to
// abandon the scan: the rest of the tree is still worth reporting. It must not
// silently vanish either, which is what Task 2's unread list is for.
func TestWalk_AnUnreadableSubdirectoryDoesNotAbortTheWalk(t *testing.T) {
	root := mkdir(t, map[string]string{
		"package-lock.json":     "{}",
		"sub/package-lock.json": "{}",
	})
	// Windows does not honour a 0o000 directory mode, so this cannot assert
	// anything there. The skip is deliberate and it is confined to this
	// function, which asserts nothing else - a skip wrapping other assertions
	// is how seven of eight mutations survived in slice 3 (CLAUDE.md). CI runs
	// on ubuntu, so the mutation below must be verified there, not here.
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions are not enforced on Windows; CI covers this")
	}
	if err := os.Chmod(filepath.Join(root, "sub"), 0o000); err != nil {
		t.Fatalf("could not drop directory permissions: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "sub"), 0o700) })
	got, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk returned %v; an unreadable subdirectory must not abort the walk", err)
	}
	if len(got) == 0 {
		t.Error("the readable root manifest was lost")
	}
}
