# Directory manifests (D26) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** A directory scan reads every lockfile it finds and names every manifest it
recognized but did not read, so a polyglot repository stops reporting a confident partial
answer as a clean one.

**Architecture:** A new `internal/cataloger/dirscan` package walks the directory once,
bounded, and dispatches each manifest it recognizes to a per-format parser (`npmlock`,
`poetrylock`, and the existing `gomod`). It returns one merged `pkgmeta.Target`, one merged
`cyclonedx.Stats`, and a list of recognized-but-unread manifests that `scancmd` discloses on
stderr. `gomod.Parse` is not rewritten; it is called by the walker.

**Tech Stack:** Go standard library only. `encoding/json` for `package-lock.json`; a
hand-written minimal TOML reader for `poetry.lock` (no new dependency — see Task 3).

## Global Constraints

Copied from the spec and CLAUDE.md. Every task's requirements implicitly include these.

- **No new third-party dependencies.** `go.mod` has no `require` block for anything but the
  container libraries already present. `CGO_ENABLED=0`.
- **A scan never fetches vulnerability data**, and a directory scan makes **no network call
  at all** and invokes **no toolchain** (D14, D23). Nothing in this plan may shell out.
- **`Components == Cataloged + every skip counter` must hold** in every cataloger. This is
  the invariant that makes "we could not evaluate this" countable.
- **Unknown severity is a band, not a default** (D17) — not touched here, but nothing may
  coerce it.
- **Version comparison stays per-ecosystem** (D9). This plan adds **no** `Comparer`: npm uses
  the existing `SemVer{}`, PyPI the existing `PEP440{}` (`internal/version/version.go:26-27`).
  If you find yourself writing a version comparison, stop — you are out of scope.
- **Results to stdout, diagnostics to stderr.** `--output json | jq` stays clean. Every
  disclosure this plan adds goes to **stderr**.
- **Deterministic, diffable output.** Walk results must be sorted; map iteration order must
  never reach the output.
- **Exit codes are contract**: `0` clean, `1` findings at/above `--fail-on`, `2` could not run
  or cannot be trusted, precedence `2 > 1 > 0` (D11).
- **Documentation is bilingual.** `README.md` and `README.ko.md` change in the same commit.
  Keep identifiers, flags and paths in English on both sides.
- **Every test must fail if the behaviour it describes is removed.** After writing one, delete
  or invert the production line it covers and confirm the suite goes red. **Report the
  mutations.**
- **A guard is not covered by the test that mentions it** (CLAUDE.md). Watch for: a field
  declared, documented as preventing the defect, and never read by an assertion; a `continue`
  or `t.Skip` sitting where the test's subject lives; presence asserted where order or count
  is the point; a format-string prefix satisfying the assertion.
- **Never assert `strings.Contains(output, x)` when another field of that same output already
  contains `x`.** Paths nest: `frontend/package-lock.json` contains `package-lock.json`, and
  `requirements.txt` appears both in a disclosure line and possibly in a path.
- `gofmt -l .` empty, `go vet ./...`, `go test ./...` green before every commit.
- Windows dev box: use `go test ./...`, **not** `-race` (no C toolchain here; CI runs it).

## The measurement this exists to fix

On a directory holding `go.mod`, `package-lock.json` and `requirements.txt`:

| | components | findings | not evaluated | exit |
|---|---|---|---|---|
| the same packages as an SBOM | 3 | **27** | 0 | 0 |
| `assay scan dir:.` | 1 | **3** | **0** | 0 |

Reproduce it before you start and after you finish. The `0 not evaluated` is the part that
makes this a defect rather than a gap.

## Prior art in this repo — read these before designing anything

- `internal/cataloger/cyclonedx/cyclonedx.go:37-41` already states D26's argument for nested
  SBOM components: reading only the top level makes packages "invisible — not skipped, but
  absent from every counter, which is worse than a counted skip because nothing in the report
  hints they existed." Follow that reasoning, and match its comment register.
- `internal/cataloger/gomod/gomod.go` — the cataloger you are extending around. Signature:
  `Parse(dir string) (pkgmeta.Target, cyclonedx.Stats, error)`.
- `internal/scancmd/scancmd.go:177-189` — the D23 disclosure. The new disclosure sits beside
  it and follows its shape: stderr, printed on **successful** scans too, never only on failure.

## File Structure

| File | Responsibility |
|---|---|
| `internal/cataloger/dirscan/walk.go` (new) | bounded directory walk; find recognized manifests; sorted results |
| `internal/cataloger/dirscan/dirscan.go` (new) | dispatch each found manifest to its parser; merge `Target` and `Stats`; return unread list |
| `internal/cataloger/npmlock/npmlock.go` (new) | parse `package-lock.json` → packages |
| `internal/cataloger/poetrylock/poetrylock.go` (new) | parse `poetry.lock` → packages |
| `internal/scancmd/scancmd.go` (modify) | call `dirscan.Parse` instead of `gomod.Parse`; disclose unread manifests |
| `README.md` / `README.ko.md` (modify) | document what a directory scan reads and does not |

`gomod`, `pkgmeta`, `version`, `matcher`, `store` and `report` are **not modified**.

---

### Task 1: The bounded walk

**Files:**
- Create: `internal/cataloger/dirscan/walk.go`, `internal/cataloger/dirscan/walk_test.go`

**Interfaces:**
- Produces:
  ```go
  // Manifest is one recognized file found by the walk.
  type Manifest struct {
      Path string // relative to the scanned root, always forward-slashed
      Kind Kind
  }
  type Kind string
  const (
      KindGoMod       Kind = "go.mod"
      KindNPMLock     Kind = "package-lock.json"
      KindPoetryLock  Kind = "poetry.lock"
      KindRequirements Kind = "requirements.txt" // recognized, never read (D26)
  )
  // Walk returns every recognized manifest under root, sorted by Path.
  func Walk(root string) ([]Manifest, error)
  ```

**Why bounded, and what the bounds are.** `node_modules`, `vendor` and `.git` are skipped: a
lockfile inside a dependency tree describes that dependency's requirements, not this
project's, and `node_modules` alone can hold tens of thousands of them. Depth is capped at 6
levels below the root so a scan cannot be made arbitrarily slow by nesting. Both limits are
disclosed by Task 5, not silent.

- [ ] **Step 1: Write the failing tests**

```go
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
		"go.mod":                       "module example.com/x\n",
		"frontend/package-lock.json":   "{}",
		"services/api/poetry.lock":     "",
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

// Sorted, so two runs over one tree cannot differ. filepath.WalkDir is already
// lexical, so this fails only if someone introduces a map or a goroutine —
// which is exactly when it needs to fail.
func TestWalk_ResultsAreSorted(t *testing.T) {
	root := mkdir(t, map[string]string{
		"z/package-lock.json": "{}",
		"a/package-lock.json": "{}",
		"m/poetry.lock":       "",
	})
	got, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a/package-lock.json", "m/poetry.lock", "z/package-lock.json"}
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
				"package-lock.json":                  "{}",
				dir + "/dep/package-lock.json":       "{}",
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
	atLimit := "a/b/c/d/e/f/package-lock.json"        // 6 directories deep
	pastLimit := "a/b/c/d/e/f/g/package-lock.json"    // 7 — one too far
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
```

- [ ] **Step 2: Run them, watch them fail**

Run: `go test ./internal/cataloger/dirscan/`
Expected: build failure — `Walk` undefined.

- [ ] **Step 3: Implement `Walk`**

Use `filepath.WalkDir` (lexical order, no `os.ReadDir` sorting needed, but sort the result
anyway so the guarantee is the function's and not the standard library's). Return
`fs.SkipDir` for excluded directories and for anything past the depth cap. Swallow per-entry
errors so one unreadable subtree does not abandon the rest; return an error only if the root
itself cannot be read.

Path separators: build `Path` with `filepath.ToSlash` so the value is identical on Windows
and Unix — the disclosure text is user-visible and its tests are byte-comparisons.

- [ ] **Step 4: Run them, watch them pass**

- [ ] **Step 5: Mutation-check before committing**

Apply, confirm red, revert:

| Mutation | Why it matters |
|---|---|
| the depth cap is `>=` instead of `>` (or vice versa) | off-by-one at the boundary |
| one of the three excluded directories is dropped | `node_modules` alone can hold thousands of lockfiles |
| results are returned unsorted | non-deterministic output |
| filename matching uses `strings.HasSuffix` instead of equality | `package-lock.json.bak` becomes a manifest |
| a per-entry error aborts the walk | one unreadable directory hides the whole tree |

- [ ] **Step 6: Commit**

---

### Task 2: `package-lock.json`

**Files:**
- Create: `internal/cataloger/npmlock/npmlock.go`, `internal/cataloger/npmlock/npmlock_test.go`

**Interfaces:**
- Produces: `func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, error)`
- Consumes: `pkgmeta.Package` (`internal/pkgmeta/package.go:12`), `cyclonedx.Stats`
  (`internal/cataloger/cyclonedx/cyclonedx.go:19`).

**The format.** `package-lock.json` v2 and v3 carry a top-level `"packages"` object keyed by
install path, where `""` is the root project and every other key looks like
`"node_modules/lodash"` or `"node_modules/a/node_modules/b"` for a nested install. Each value
carries `"version"`. v1 files instead carry `"dependencies"`, keyed by bare package name and
nested recursively. Support both: `lockfileVersion` says which, and real repositories still
contain v1.

**What each package becomes.** `Name` is the last `node_modules/`-separated segment (scoped
packages keep their `@scope/name` form), `Version` is the `"version"` string verbatim,
`Type` is `"npm"`, `Ecosystem` is `"npm"`, `PURL` is `pkg:npm/<name>@<version>`, and
`Locations` is one entry with the lockfile's own path. Do **not** set `Source` — that is for
distro source packages (D8) and has no meaning here.

**What is skipped, and counted.** The root entry (`""`) is not a dependency: it is the
project itself and has no version to match. Count it in `Components` and in
`SkippedNoVersion`, never in `Cataloged`, so the invariant holds. An entry with `"link": true`
is a workspace symlink to a local directory, not a registry package — same treatment. So is
any entry with an empty `"version"`.

- [ ] **Step 1: Write the failing tests**

```go
package npmlock

import (
	"os"
	"path/filepath"
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
```

Add `"strings"` to the test imports, and `"runtime"` to Task 1's.

- [ ] **Step 2: Run them, watch them fail**
- [ ] **Step 3: Implement**

Decode into a struct with both `Packages map[string]lockEntry` and
`Dependencies map[string]lockDep`; use whichever is populated rather than branching on
`lockfileVersion`, since the field is what actually determines the shape. Walk
`Dependencies` recursively for the v1 case.

Iterate map keys in **sorted** order so the returned slice is deterministic — a map range
here would reach the report.

- [ ] **Step 4: Run them, watch them pass**
- [ ] **Step 5: Mutation-check**

| Mutation | Must fail |
|---|---|
| the `""` root entry is cataloged as a package | the count and the invariant |
| the scope is stripped from `@scope/pkg` | the scoped-package assertion |
| the whole install path becomes the name | the nested-install test |
| v1 `dependencies` is not walked | the v1 test |
| nested v1 dependencies are not recursed | the v1 test |
| an unmatchable entry is dropped instead of counted | the invariant |
| malformed JSON returns an empty slice and nil error | the malformed test |
| the error is built without the path, e.g. `fmt.Errorf("parse package-lock.json: %w", err)` | the malformed test — it asserts the path, so a hard-coded filename does not satisfy it |
| packages are emitted in map order | add a fixture with keys whose sorted order differs from insertion |

- [ ] **Step 6: Commit**

---

### Task 3: `poetry.lock`

**Files:**
- Create: `internal/cataloger/poetrylock/poetrylock.go`,
  `internal/cataloger/poetrylock/poetrylock_test.go`

**Interfaces:**
- Produces: `func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, error)`

**No TOML dependency.** `poetry.lock` is TOML, and adding a TOML library is a real dependency
decision this plan does not make. The subset needed is small and rigid: a sequence of
`[[package]]` tables, each with `name = "..."` and `version = "..."` as quoted single-line
strings. Parse that subset line by line and **reject anything you do not understand rather
than guessing** — an unrecognized line inside a `[[package]]` block is ignored, but a
`[[package]]` block that ends without both a name and a version is a counted skip, not a
silent drop.

Write the reason in the code: a hand-rolled reader is chosen over a dependency *and* over
`encoding/json`-style tolerance, because the failure mode of guessing at TOML is a wrong
version, and a wrong version is a silent false negative.

**Name normalization.** PyPI names are normalized per PEP 503 at match time, not at catalog
time (`internal/pkgmeta/purl.go:110` — check what it does and do not duplicate it). Emit the
name as written; let the existing normalization handle it.

- [ ] **Step 1: Write the failing tests**

```go
package poetrylock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "poetry.lock")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParse_ReadsEveryPackageBlock(t *testing.T) {
	p := write(t, `# This file is automatically @generated by Poetry.
[[package]]
name = "django"
version = "3.2.12"
description = "A high-level Python Web framework."
optional = false
python-versions = ">=3.6"

[[package]]
name = "urllib3"
version = "1.26.5"
optional = false

[metadata]
lock-version = "2.0"
`)
	pkgs, stats, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, pk := range pkgs {
		got[pk.Name] = pk.Version
	}
	if got["django"] != "3.2.12" || got["urllib3"] != "1.26.5" {
		t.Errorf("packages = %v, want django 3.2.12 and urllib3 1.26.5", got)
	}
	if len(pkgs) != 2 {
		t.Errorf("got %d packages, want 2 — [metadata] is not a package", len(pkgs))
	}
	if pkgs[0].Ecosystem != "PyPI" || pkgs[0].Type != "pypi" {
		t.Errorf("Ecosystem/Type = %q/%q, want PyPI/pypi", pkgs[0].Ecosystem, pkgs[0].Type)
	}
	if stats.Components != stats.Cataloged+stats.SkippedNoPURL+
		stats.SkippedNoVersion+stats.SkippedUnsupportedEcosystem {
		t.Errorf("the Components == Cataloged + skips invariant does not hold: %+v", stats)
	}
}

// A key that appears AFTER the block it belongs to would be attributed to the
// next block by a parser that does not reset state at [[package]].
func TestParse_KeysDoNotLeakBetweenBlocks(t *testing.T) {
	p := write(t, `[[package]]
name = "first"
version = "1.0.0"

[[package]]
name = "second"
version = "2.0.0"
`)
	pkgs, _, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 || pkgs[0].Version != "1.0.0" || pkgs[1].Version != "2.0.0" {
		t.Errorf("packages = %+v, want first/1.0.0 and second/2.0.0", pkgs)
	}
}

// A block missing a version cannot be matched. Counted, never dropped.
func TestParse_ABlockWithoutAVersionIsCountedNotDropped(t *testing.T) {
	p := write(t, `[[package]]
name = "nameonly"

[[package]]
name = "complete"
version = "1.0.0"
`)
	pkgs, stats, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "complete" {
		t.Fatalf("cataloged %+v, want only 'complete'", pkgs)
	}
	if stats.Components != 2 {
		t.Errorf("Components = %d, want 2 — the incomplete block was still seen",
			stats.Components)
	}
	if stats.SkippedNoVersion != 1 {
		t.Errorf("SkippedNoVersion = %d, want 1", stats.SkippedNoVersion)
	}
}

// A "name" or "version" key inside a nested table such as [package.source]
// belongs to that table, not to the package. Attributing it to the package
// yields a wrong version, which is a silent false negative.
func TestParse_KeysInsideNestedTablesAreNotThePackages(t *testing.T) {
	p := write(t, `[[package]]
name = "real"
version = "1.0.0"

[package.source]
type = "git"
url = "https://example.com/x.git"
reference = "main"
version = "9.9.9"
`)
	pkgs, _, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	if pkgs[0].Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0 — the version inside [package.source] "+
			"belongs to that table, not to the package", pkgs[0].Version)
	}
}

// A file that is not a poetry.lock at all must not read as "no packages".
func TestParse_AFileWithNoPackageBlocksIsAnError(t *testing.T) {
	p := write(t, "this is not a lockfile\n")
	_, _, err := Parse(p)
	if err == nil {
		t.Fatal("Parse returned nil error for a file with no [[package]] blocks — " +
			"an unreadable lockfile must not read as a clean scan")
	}
	// The full path, not the bare filename: a hard-coded "poetry.lock" in the
	// error's own format string would satisfy the weaker check.
	if !strings.Contains(err.Error(), p) {
		t.Errorf("error %q does not name the file it failed on (%s)", err, p)
	}
}
```

- [ ] **Step 2: Run them, watch them fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run them, watch them pass**
- [ ] **Step 5: Mutation-check**

| Mutation | Must fail |
|---|---|
| state is not reset at `[[package]]` | the leak test |
| a nested `[table]` is treated as still inside the package | the nested-table test |
| a version-less block is dropped instead of counted | the invariant |
| no `[[package]]` blocks returns an empty slice and nil error | the not-a-lockfile test |
| `[metadata]` is treated as a package | the count in the first test |

- [ ] **Step 6: Commit**

---

### Task 4: Dispatch and merge

**Files:**
- Create: `internal/cataloger/dirscan/dirscan.go`, `internal/cataloger/dirscan/dirscan_test.go`

**Interfaces:**
- Consumes: `Walk` (Task 1), `npmlock.Parse` (Task 2), `poetrylock.Parse` (Task 3),
  `gomod.Parse` (existing, `(pkgmeta.Target, cyclonedx.Stats, error)`).
- Produces:
  ```go
  // Unread is a manifest that was recognized and deliberately not parsed.
  type Unread struct {
      Path   string
      Reason string // e.g. "not a lockfile: versions may be ranges"
  }
  func Parse(root string) (pkgmeta.Target, cyclonedx.Stats, []Unread, error)
  ```

**Merging.** Concatenate packages from every manifest and sum every `Stats` field, so the
`Components == Cataloged + skips` invariant survives the merge — if it holds for each part it
holds for the sum. Sort the merged package list (by ecosystem, name, version, then location)
so output does not depend on walk order beyond what Task 1 already guarantees.

**`Target.Distro` stays empty.** A directory is not an operating system (D7).

**A parse failure of one manifest does not abandon the others**, but it is not silent either:
it becomes an `Unread` entry whose reason is the error. That is the difference between "we
did not look" and "we looked and could not read it", and both must reach the user.

- [ ] **Step 1: Write the failing tests**

```go
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

// One unreadable manifest must not take the others down with it, and must not
// vanish: "we looked and could not read it" is a different fact from "we did
// not look", and both belong in the report.
func TestParse_AnUnparseableManifestBecomesUnreadNotAnAbort(t *testing.T) {
	root := mkdir(t, map[string]string{
		"package-lock.json":          `{"lockfileVersion":3,"packages":{"":{"version":"1"},"node_modules/ok":{"version":"1.0.0"}}}`,
		"broken/package-lock.json":   `{"lockfileVersion":3, `,
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
```

Reuse Task 1's `mkdir` helper (same package). Add `"fmt"` to the imports.

- [ ] **Step 2-4: fail, implement, pass**
- [ ] **Step 5: Mutation-check**

| Mutation | Must fail |
|---|---|
| only the first manifest of each kind is parsed | the polyglot test |
| `go.mod` is parsed but lockfiles are not (today's behaviour) | the polyglot test |
| the unread list is returned empty | the unread assertions |
| an unread entry's reason is dropped | the reason assertions |
| stats are overwritten rather than summed | the invariant |
| a parse error aborts the whole scan | the unparseable test |
| the merged package list is not sorted | the determinism test |

- [ ] **Step 6: Commit**

---

### Task 5: Wire it up, and disclose

**Files:**
- Modify: `internal/scancmd/scancmd.go`, `internal/scancmd/scancmd_test.go`
- Modify: `README.md`, `README.ko.md`

**The change.** `case source.TargetDirectory:` calls `dirscan.Parse(path)` instead of
`gomod.Parse(path)`. The D23 disclosure at `scancmd.go:177-189` currently says
`go.mod names %d module(s)`; it must keep saying something true when the directory has no
`go.mod` at all. Rework it so the Go-specific sentence appears only when a `go.mod` was
actually read, and add the unread disclosure beside it.

**Disclosure format** — stderr, one line per unread manifest, on **successful** scans too:

```
scanned dir:. as a directory
go.mod names 1 module(s); this is what was requested, not what a build links - scan the built binary for that
not read: requirements.txt (not a lockfile: versions may be ranges, not versions)
```

Name the file. A count alone tells a reader something is missing without telling them what to
do about it.

- [ ] **Step 1: Write the failing test**

```go
// The end-to-end shape of D26: a polyglot directory reports BOTH ecosystems'
// findings, and names what it did not read.
//
// Before this, the same directory reported the Go packages, said
// "0 not evaluated", and exited 0 while npm and PyPI findings went
// unmentioned.
func TestRun_DirectoryScanReadsLockfilesAndDisclosesTheRest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"),
		"module example.com/poly\n\ngo 1.22\n\nrequire example.com/critical v1.0.0\n")
	writeFile(t, filepath.Join(dir, "package-lock.json"),
		`{"lockfileVersion":3,"packages":{"":{"version":"1.0.0"},`+
			`"node_modules/example.com/medium":{"version":"1.0.0"}}}`)
	writeFile(t, filepath.Join(dir, "requirements.txt"), "Django==3.2.12\n")

	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-critical", pkg: "critical", fixed: "2.0.0", vectors: []string{vecCritical}},
	})
	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, "dir:"+dir, Options{}, &out, &errOut)
	if code != 0 {
		t.Fatalf("Run = %d, want 0; stderr: %s", code, errOut.String())
	}
	// Asserted on the rendered pair, not on "requirements.txt" alone: that
	// string also appears in any path the walk prints, so a bare Contains
	// would pass from the wrong line.
	if !strings.Contains(errOut.String(), "not read: requirements.txt") {
		t.Errorf("the scan did not name the manifest it declined to read:\n%s",
			errOut.String())
	}
	// The npm package reached the matcher, which is the half that removes the
	// silent miss.
	if !strings.Contains(out.String(), "example.com/medium") {
		t.Errorf("the lockfile's package is absent from the report:\n%s", out.String())
	}
}

// A directory with only a lockfile and no go.mod must not claim anything about
// go.mod. The D23 line is true only when a go.mod was read.
func TestRun_NoGoModMeansNoGoModDisclosure(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"),
		`{"lockfileVersion":3,"packages":{"":{"version":"1.0.0"},`+
			`"node_modules/example.com/medium":{"version":"1.0.0"}}}`)
	db := buildMatrixDB(t, []matrixAdv{})
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, "dir:"+dir, Options{}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0; stderr: %s", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "go.mod names") {
		t.Errorf("the scan claimed something about go.mod in a directory that has "+
			"none:\n%s", errOut.String())
	}
}
```

`writeFile` is a small helper — add it if the file has none. `buildMatrixDB`, `matrixAdv` and
`vecCritical` already exist in `scancmd_test.go`.

- [ ] **Step 2-4: fail, implement, pass**

- [ ] **Step 5: Update both READMEs, same commit**

The "Binaries and directories" section (`README.md:132`, `README.ko.md:132`) documents what a
directory scan reads. Extend it: lockfiles read, `requirements.txt` named and not read and
why, the bounded walk and its exclusions. Keep the existing D23 table.

- [ ] **Step 6: Mutation-check**

| Mutation | Must fail |
|---|---|
| the unread disclosure is not printed | the disclosure test |
| the disclosure prints a count instead of the filename | the disclosure test |
| the disclosure goes to stdout | `--output json` cleanliness (there is an existing test for this — find it and confirm it fires) |
| the D23 line prints when no `go.mod` was read | the no-go.mod test |
| `dirscan.Parse` is called but its packages are dropped | the report assertion |

- [ ] **Step 7: Commit**

---

### Task 6: Reproduce the measurement

**Files:**
- Modify: `docs/superpowers/specs/2026-07-29-assay-roadmap.md` and `.ko.md` (D26's table)

**Do not delegate.** This checks the plan's own headline claim.

- [ ] **Step 1: Build the same fixture D26 measured**

A directory with `go.mod` (requiring `gopkg.in/yaml.v2 v2.2.1`), `package-lock.json`
(`lodash 4.17.11`), and `requirements.txt` (`Django==3.2.12`), against a real database.

- [ ] **Step 2: Scan it three ways and record the numbers**

`dir:` before this slice (27 vs 3 was the measurement), `dir:` after, and the same packages as
an SBOM. The `dir:` and SBOM numbers should now agree except for `requirements.txt`, which is
disclosed rather than read.

- [ ] **Step 3: Add the after-column to D26's table in both languages**

If the numbers do not match what D26 predicted, **the measurement wins** — correct the
decision record rather than the measurement, the way the D25 fixed-version figure was
corrected.

- [ ] **Step 4: Commit**

---

## Done when

- `assay scan dir:<polyglot repo>` reports Go, npm and PyPI packages from one walk.
- The same directory's `dir:` and SBOM scans agree on findings, except for manifests
  disclosed as unread.
- Every manifest recognized and not read is named on stderr with a reason, on successful
  scans too.
- `node_modules`, `vendor` and `.git` are never descended into; depth is capped and the cap is
  tested at its boundary.
- `Components == Cataloged + every skip counter` holds in each new cataloger and after the
  merge.
- A directory with no recognized manifest exits 2, not 0.
- Every mutation listed in every task turns the suite red.
- `README.md` and `README.ko.md` describe what a directory scan reads and does not.

## Not in this plan

`requirements.txt` parsing — it needs its own decision about unpinned constraints, recorded in
`docs/deferred-decisions.md`. Yarn and pnpm lockfiles. `Pipfile.lock`. Any new `Comparer`
(D9): npm and PyPI comparisons already exist and are not touched. Changing what a **binary**
scan reads (D23/D24 are settled). Making `go.mod` resolution more accurate — that is D23's
recorded limitation, unchanged here.
