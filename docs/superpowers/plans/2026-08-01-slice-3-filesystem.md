# Slice 3 — Filesystem and binary targets

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `assay scan ./bin/assay` and `assay scan dir:./project` produce findings, with the
Go toolchain matched as `stdlib`.

**Architecture:** Two new catalogers behind the existing `Target{Distro, []Package}` boundary
— one reading `debug/buildinfo` from a binary, one parsing `go.mod` from a directory — plus a
target classifier that decides which of the five target kinds a bare path is (D22). Nothing
downstream changes: the matcher, the comparers, the store and every renderer already handle
the `Go` ecosystem, because slice 1 shipped it.

**Tech Stack:** Go standard library only. `debug/buildinfo` for binaries, hand-written
`go.mod` parsing for directories (D23 — no `golang.org/x/mod`, no shelling out to `go`).

## Global Constraints

- No new third-party dependencies. `go.mod`'s `require` block must not grow. `CGO_ENABLED=0`.
- A scan never fetches vulnerability data (D14). A filesystem or binary scan makes **no
  network call at all** — no toolchain invocation, no module download, nothing.
- Exit codes are contract: `0` clean, `1` findings at or above `--fail-on`, `2` could not run
  or cannot be trusted. Precedence `2 > 1 > 0` (D11).
- Results to stdout, diagnostics to stderr.
- Packages that cannot be evaluated are reported as skipped **with a count**, never folded
  silently into a clean verdict. That obligation is on every renderer.
- Version comparison stays per-ecosystem (D9). Do not add or modify a `Comparer`; the `Go`
  comparer already exists and is correct. Normalization happens at **catalog** time, before
  a version reaches the matcher.
- `Package.Ecosystem` is the OSV key resolved at catalog time. For everything in this slice
  it is `"Go"`.
- Every test must fail if the behaviour it describes is removed. After writing a test, delete
  or invert the production line it covers and confirm the suite goes red. Report the
  mutations tried.
- **Never assert `strings.Contains(output, x)` when another field in that output already
  contains `x` as a substring.** Module paths nest (`golang.org/x/sys` contains
  `golang.org/x`), and `1.26` is a substring of `1.26.4`. Assert the specific field.
- **Never type an escape sequence literally inside a script that generates a file.** Assemble
  it (`chr(92) + "n"`) and verify by scanning the written file. Use the Edit tool instead
  where possible.
- Documentation is bilingual: `README.md` and `README.ko.md` change in the same commit.
- `gofmt -l .` empty, `go vet ./...` clean, `go test ./...` green before every commit.

## Measured inputs

Everything below was measured on this repository at `e220a8f`, not assumed.

| Question | Answer |
|---|---|
| modules `debug/buildinfo` reports for `assay` itself | **10**, plus the main module |
| modules `go.mod`'s require blocks name | **11** (2 direct, 9 indirect) |
| modules `go list -m all` reports | **52** |
| in the module graph but not linked | **41** |
| main module version in the binary | `v0.0.0-20260801032351-e220a8f9e81b` — a real pseudo-version, **not** `(devel)` |
| `stdlib` advisories in the live database | **159** |
| stdlib advisory version shape | `introduced="1.16.0-0"`, `fixed="1.16.1"` — no `go` prefix |
| `GoVersion` in the binary | `go1.26.4` |

The `Go` comparer's behaviour on the shapes this slice will hand it, measured directly:

| input | result |
|---|---|
| `v1.9.4` vs `1.9.3` | `1` — the `v` prefix is already handled |
| `v29.5.3+incompatible` vs `29.2.0` | `1` — `+incompatible` is already handled |
| `1.26.4` vs `1.21.0` | `1` |
| `1.21.0-rc.1` vs `1.21.0` | `-1` — pre-release sorts below, correctly |
| `1.22.0-beta.1` vs `1.21.0` | `1` |
| `1.16.0-0` vs `1.21.0` | `-1` |
| `go1.26.4` vs `1.26.5` | **error** — `core identifier "go1": invalid version` |
| `1.26` vs `1.21.0` | **error** — `core needs exactly three identifiers` |
| `1.21rc1` vs `1.21.0` | **error** — same |
| `1.22beta1` vs `1.21.0` | **error** — same |

The four errors are the entire normalization job in Task 3. They fail loudly, which is the
good case; the risk is normalizing them to something that parses but orders wrongly.

---

## File structure

| File | Responsibility |
|---|---|
| `internal/source/classify.go` (new) | D22: one target string → one `TargetKind`, by prefix or by content |
| `internal/source/image.go` (modify) | `TargetKind` gains `TargetDirectory` and `TargetGoBinary`; `ClassifyTarget` moves out |
| `internal/cataloger/gobinary/gobinary.go` (new) | `debug/buildinfo` → `pkgmeta.Target`, including `stdlib` |
| `internal/cataloger/gobinary/goversion.go` (new) | D24: `go1.21rc1` → `1.21.0-rc.1`, alone and testable |
| `internal/cataloger/gomod/gomod.go` (new) | D23: `go.mod` → `pkgmeta.Target` |
| `internal/scancmd/scancmd.go` (modify) | route the two new kinds; disclose what was read |
| `README.md`, `README.ko.md` (modify) | the new targets, and D23's limitation stated plainly |

---

### Task 1: Target classification (D22)

**Do not delegate.** This decides what a bare path *means*, and getting it wrong sends every
downstream error message after the wrong problem.

**Files:**
- Create: `internal/source/classify.go`, `internal/source/classify_test.go`
- Modify: `internal/source/image.go` — remove `ClassifyTarget`, extend `TargetKind`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces:
  ```go
  type TargetKind int
  const (
      TargetImage TargetKind = iota
      TargetSBOM
      TargetDirectory
      TargetGoBinary
  )
  func (k TargetKind) String() string  // "image" | "sbom" | "directory" | "go-binary"
  func Classify(target string) (TargetKind, string, error)
  ```
  `Classify` returns the kind, the path or reference with any `file:` / `dir:` / `sbom:`
  prefix **stripped**, and an error naming every kind it tried when nothing matched.
  `docker-archive:` and `oci-dir:` prefixes are returned **unstripped** with `TargetImage`,
  because `source.Open` parses them itself.

- [ ] **Step 1: Write the failing tests**

```go
package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The prefixes are an escape hatch from the sniff, so they must win outright —
// including when the sniff would have said something else, which is the only
// situation in which a user reaches for them.
func TestClassify_ExplicitPrefixesOverrideTheContent(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "s.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		in       string
		wantKind TargetKind
		wantPath string
	}{
		{"sbom:" + sbom, TargetSBOM, sbom},
		{"dir:" + dir, TargetDirectory, dir},
		{"file:" + sbom, TargetGoBinary, sbom},
		// A prefix on a path that does not exist is still that kind: the
		// error the caller then reports is "cannot open", which is true,
		// rather than "not a recognised target", which is not.
		{"dir:/does/not/exist", TargetDirectory, "/does/not/exist"},
		{"file:/does/not/exist", TargetGoBinary, "/does/not/exist"},
	} {
		gotKind, gotPath, err := Classify(tt.in)
		if err != nil {
			t.Errorf("Classify(%q): %v", tt.in, err)
			continue
		}
		if gotKind != tt.wantKind {
			t.Errorf("Classify(%q) kind = %v, want %v", tt.in, gotKind, tt.wantKind)
		}
		if gotPath != tt.wantPath {
			t.Errorf("Classify(%q) path = %q, want %q", tt.in, gotPath, tt.wantPath)
		}
	}
}

// Image prefixes keep their prefix, because source.Open re-parses it. Stripping
// it here would send an oci-dir: layout to the registry path.
func TestClassify_ImagePrefixesAreLeftIntact(t *testing.T) {
	for _, in := range []string{"docker-archive:/tmp/x.tar", "oci-dir:/tmp/layout"} {
		kind, path, err := Classify(in)
		if err != nil {
			t.Errorf("Classify(%q): %v", in, err)
			continue
		}
		if kind != TargetImage {
			t.Errorf("Classify(%q) kind = %v, want image", in, kind)
		}
		if path != in {
			t.Errorf("Classify(%q) path = %q, want it unchanged", in, path)
		}
	}
}

// A bare path is decided by content, in a fixed order. The fixture for the
// binary case is this test binary itself: os.Executable() is a real Go binary
// with real build info, so the test cannot pass against a stub that says yes
// to everything.
func TestClassify_BarePathsAreSniffed(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name string
		in   string
		want TargetKind
	}{
		{"a Go binary", self, TargetGoBinary},
		{"a CycloneDX document", sbom, TargetSBOM},
		{"a directory", dir, TargetDirectory},
		{"a registry reference", "alpine:3.19", TargetImage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := Classify(tt.in)
			if err != nil {
				t.Fatalf("Classify(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("Classify(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// A file that exists and is none of the three is an error naming all three,
// not a silent fallthrough to whichever branch is last. Falling through to
// SBOM is what happens today, and it reports a malformed JSON document for a
// file that was never meant to be one.
func TestClassify_AnUnrecognisedFileIsAnErrorNamingWhatWasTried(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mystery.bin")
	if err := os.WriteFile(path, []byte("not a go binary, not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Classify(path)
	if err == nil {
		t.Fatal("Classify of an unrecognised file succeeded")
	}
	for _, want := range []string{"Go binary", "CycloneDX", "sbom:", "file:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q - the user cannot tell what to do next", err, want)
		}
	}
}

// The kind is printed in the scan's own output so a wrong guess is visible
// rather than inferred from a confusing downstream error, which makes these
// names contract.
func TestTargetKindString(t *testing.T) {
	for k, want := range map[TargetKind]string{
		TargetImage:     "image",
		TargetSBOM:      "sbom",
		TargetDirectory: "directory",
		TargetGoBinary:  "go-binary",
	} {
		if got := k.String(); got != want {
			t.Errorf("TargetKind(%d).String() = %q, want %q", int(k), got, want)
		}
	}
	if got := TargetKind(99).String(); !strings.Contains(got, "99") {
		t.Errorf("TargetKind(99).String() = %q, want something naming the value", got)
	}
}
```

- [ ] **Step 2: Run them, watch them fail**

Run: `go test ./internal/source/ -run TestClassify`
Expected: FAIL — `undefined: Classify`, `undefined: TargetDirectory`.

- [ ] **Step 3: Implement**

```go
// Package-level doc goes on classify.go explaining D22.
func Classify(target string) (TargetKind, string, error) {
	// Image prefixes first and returned intact: source.Open parses them
	// itself, and stripping one here would send an oci-dir: layout down the
	// registry path.
	if classify(target) != kindRegistry {
		return TargetImage, target, nil
	}
	for _, p := range []struct {
		prefix string
		kind   TargetKind
	}{
		{"sbom:", TargetSBOM},
		{"dir:", TargetDirectory},
		{"file:", TargetGoBinary},
	} {
		if rest, ok := strings.CutPrefix(target, p.prefix); ok {
			return p.kind, rest, nil
		}
	}

	info, err := os.Stat(target)
	if err != nil {
		// Not a path at all, so it is a registry reference. A typo'd path
		// reaching the registry is the pre-existing behaviour and stays.
		return TargetImage, target, nil
	}
	if info.IsDir() {
		return TargetDirectory, target, nil
	}
	if _, err := buildinfo.ReadFile(target); err == nil {
		return TargetGoBinary, target, nil
	}
	if looksLikeCycloneDX(target) {
		return TargetSBOM, target, nil
	}
	return 0, "", fmt.Errorf(
		"%s is a file, but not a Go binary and not a CycloneDX document; "+
			"use sbom:, file: or dir: to say which it is", target)
}
```

`looksLikeCycloneDX` reads at most 512 bytes and looks for `"bomFormat"`. It must not parse
the whole document: a 40 MB SBOM should not be read twice, and the classifier's job is to
choose a parser, not to validate.

- [ ] **Step 4: Run the tests, watch them pass**

Run: `go test ./internal/source/`

- [ ] **Step 5: Update the one existing caller**

`internal/scancmd/scancmd.go` calls `source.ClassifyTarget(target) == source.TargetImage`.
Change it to the two-value form. Do not change any behaviour yet — the two new kinds fall
through to the SBOM branch in this task and are routed in Task 5. Confirm `go test ./...` is
still green, which proves the classifier is a drop-in for the old one on every existing path.

- [ ] **Step 6: Commit**

```bash
git add internal/source/ internal/scancmd/scancmd.go
git commit -m "feat: classify targets by content, with prefixes to override (D22)"
```

---

### Task 2: The Go binary cataloger

**Files:**
- Create: `internal/cataloger/gobinary/gobinary.go`, `…/gobinary_test.go`

**Interfaces:**
- Consumes: `pkgmeta.Target`, `pkgmeta.Package`, `pkgmeta.Location`, `cyclonedx.Stats`
  (existing types — read `internal/pkgmeta/package.go` before writing anything).
- Produces:
  ```go
  func Parse(path string) (pkgmeta.Target, cyclonedx.Stats, error)
  ```
  Ecosystem `"Go"`, type `"golang"`, purl `pkg:golang/<module>@<version>`,
  one `Location{Path: path}` per package with no layer digest.

**What the fixture is.** Build a real binary in the test with `go build`, from a tiny module
inside `t.TempDir()`, and read it back. A hand-rolled byte fixture would test the parser
against a file no compiler produced. `os.Executable()` also works and is cheaper — the test
binary itself has real build info — but a purpose-built one lets the test assert *which*
modules appear.

- [ ] **Step 1: Write the failing tests**

```go
// find returns the package with the given name, or fails. Never assert with
// strings.Contains over the whole inventory: module paths nest, so
// "golang.org/x/sys" is satisfied by "golang.org/x/sys/unix" and every
// assertion would pass from the wrong package.
func find(t *testing.T, tgt pkgmeta.Target, name string) pkgmeta.Package {
	t.Helper()
	for _, p := range tgt.Packages {
		if p.Name == name {
			return p
		}
	}
	var have []string
	for _, p := range tgt.Packages {
		have = append(have, p.Name)
	}
	t.Fatalf("no package named %q; got %v", name, have)
	return pkgmeta.Package{}
}

// The main module is a package too. It carries a real pseudo-version derived
// from VCS (v0.0.0-20260801032351-e220a8f9e81b on this repo), not "(devel)",
// so it is comparable and an advisory against it would match. Dropping it
// means a scan of an application never reports the application.
func TestParse_IncludesTheMainModule(t *testing.T) {
	bin := buildFixture(t, "module example.test/app\n\ngo 1.26\n",
		"package main\n\nfunc main() {}\n")

	tgt, stats, err := Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	main := find(t, tgt, "example.test/app")
	if main.Ecosystem != "Go" {
		t.Errorf("ecosystem = %q, want Go", main.Ecosystem)
	}
	if main.Type != "golang" {
		t.Errorf("type = %q, want golang", main.Type)
	}
	// Built outside a VCS checkout, the main module is "(devel)" - which is
	// not a version, so it is a counted skip rather than a package claiming
	// a version nothing can compare.
	if main.Version == "(devel)" {
		t.Error("(devel) was reported as a version instead of being skipped")
	}
	if len(main.Locations) != 1 || main.Locations[0].Path != bin {
		t.Errorf("locations = %+v, want one naming %s", main.Locations, bin)
	}
	if main.Locations[0].LayerDigest != "" {
		t.Errorf("layer digest = %q, want empty outside an image scan",
			main.Locations[0].LayerDigest)
	}
	if stats.Components != len(tgt.Packages)+stats.SkippedNoVersion {
		t.Errorf("stats do not add up: %+v with %d packages", stats, len(tgt.Packages))
	}
}

// Every dependency the linker kept, with the version the linker used - not
// what go.mod requested. The fixture imports the dependency so the linker
// actually keeps it; an unused require is absent from build info, which is
// the whole difference between this cataloger and the go.mod one.
func TestParse_ReportsLinkedDependencies(t *testing.T) {
	// Uses a module already in this repo's module cache, so no download.
	bin := buildFixture(t,
		"module example.test/app\n\ngo 1.26\n\nrequire go.etcd.io/bbolt v1.5.0\n",
		"package main\n\nimport _ \"go.etcd.io/bbolt\"\n\nfunc main() {}\n")

	tgt, _, err := Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	dep := find(t, tgt, "go.etcd.io/bbolt")
	if dep.Version != "v1.5.0" {
		t.Errorf("version = %q, want v1.5.0 - the version the linker used", dep.Version)
	}
	if want := "pkg:golang/go.etcd.io/bbolt@v1.5.0"; dep.PURL != want {
		t.Errorf("purl = %q, want %q", dep.PURL, want)
	}
}

// A replace directive means the module you are running is not the module the
// path names. Reporting the replaced-away path would look up advisories for
// code that is not in this binary - a false positive - while missing the
// advisories for the code that IS there - a false negative, silent.
func TestParse_FollowsReplaceDirectives(t *testing.T) {
	bin := buildFixture(t,
		"module example.test/app\n\ngo 1.26\n\n"+
			"require golang.org/x/sync v0.20.0\n\n"+
			"replace golang.org/x/sync => golang.org/x/sync v0.21.0\n",
		"package main\n\nimport _ \"golang.org/x/sync/errgroup\"\n\nfunc main() {}\n")

	tgt, _, err := Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	dep := find(t, tgt, "golang.org/x/sync")
	if dep.Version != "v0.21.0" {
		t.Errorf("version = %q, want v0.21.0 - the replacement, not the replaced", dep.Version)
	}
	// And the replaced-away version must not also be present: two entries for
	// one module would double-count it in every summary.
	n := 0
	for _, p := range tgt.Packages {
		if p.Name == "golang.org/x/sync" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("golang.org/x/sync appears %d times, want 1", n)
	}
}

// Not a Go binary, a directory, and a missing file are three different
// failures and the message must say which, because the user's next action
// differs for each.
func TestParse_Rejects(t *testing.T) {
	dir := t.TempDir()
	notGo := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(notGo, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ name, path string }{
		{"a file that is not a Go binary", notGo},
		{"a directory", dir},
		{"a path that does not exist", filepath.Join(dir, "absent")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Parse(tt.path)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded", tt.path)
			}
			if !strings.Contains(err.Error(), tt.path) {
				t.Errorf("error %q does not name the path", err)
			}
		})
	}
}
```

Each of these needs a real built binary. Write one helper:

```go
// buildFixture compiles a module with the given go.mod and main.go into
// t.TempDir() and returns the binary's path.
//
// It shells out to `go build`, which is fine in a TEST: the constraint D23
// records is that the SCANNER must not need a toolchain, not that the suite
// cannot use one. A hand-rolled byte fixture would test this parser against a
// file no compiler ever produced.
//
// GOFLAGS=-mod=mod and the shared module cache keep it offline - every module
// used by these fixtures is already required by this repository.
func buildFixture(t *testing.T, gomod, mainGo string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH; this test needs a toolchain to build its fixture")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  gomod,
		"main.go": mainGo,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(dir, "app.bin")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	// GOFLAGS=-mod=mod lets the build resolve from the module cache without
	// a go.sum; GOPROXY=off makes a cache miss an error rather than a silent
	// network fetch, so a fixture that would need the network fails loudly
	// here instead of making the suite depend on it.
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off", "GONOSUMDB=*", "GONOSUMCHECK=1", "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build failed (%v); fixture needs modules not in the local cache:\n%s", err, out)
	}
	return bin
}
```

A skip here is honest — the fixture could not be built — but it must say why. A silently
skipped test is a test that does not exist.

- [ ] **Step 2: Run them, watch them fail**

- [ ] **Step 3: Implement**

```go
func Parse(path string) (pkgmeta.Target, cyclonedx.Stats, error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("read build info from %s: %w", path, err)
	}
	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
	)
	add := func(name, version string) {
		stats.Components++
		if version == "" || version == "(devel)" {
			// "(devel)" is what an un-stamped main module reports. It is not
			// a version any advisory range can be compared against, so it is
			// a counted skip rather than a package with a version that looks
			// real.
			stats.SkippedNoVersion++
			return
		}
		stats.Cataloged++
		pkgs = append(pkgs, pkgmeta.Package{
			Name:      name,
			Version:   version,
			Type:      "golang",
			Ecosystem: "Go",
			PURL:      "pkg:golang/" + name + "@" + version,
			Locations: []pkgmeta.Location{{Path: path}},
		})
	}

	add(bi.Main.Path, bi.Main.Version)
	for _, d := range bi.Deps {
		// A replaced module is a different module: reporting the path that
		// was replaced away would look up advisories against code that is
		// not in this binary.
		if d.Replace != nil {
			d = d.Replace
		}
		add(d.Path, d.Version)
	}
	// stdlib is added in Task 3.
	return pkgmeta.Target{Packages: pkgs}, stats, nil
}
```

`Distro` stays nil: a binary is not a distro (D7).

- [ ] **Step 4: Run the tests, watch them pass**

- [ ] **Step 5: Commit**

```bash
git add internal/cataloger/gobinary/
git commit -m "feat: catalog a Go binary from its build info"
```

---

### Task 3: The toolchain as `stdlib` (D24)

**Do not delegate.** This is version normalization feeding a comparer, and CLAUDE.md reserves
that for the main loop: a wrong ordering is a **false negative**, silent, and it is exactly
what the per-ecosystem `Comparer` design exists to prevent (D9).

**Files:**
- Create: `internal/cataloger/gobinary/goversion.go`, `…/goversion_test.go`
- Modify: `internal/cataloger/gobinary/gobinary.go` — add the `stdlib` package

**Interfaces:**
- Produces, both unexported and used only inside this package:
  ```go
  func normalizeGoVersion(v string) (string, bool)
  func addStdlib(pkgs *[]pkgmeta.Package, stats *cyclonedx.Stats, goVersion, path string)
  ```
  `addStdlib` is separate from `Parse` so the cannot-normalize path is reachable from a
  test without a toolchain that reports a development version on demand.

**Why this is worth its own task.** 159 advisories in the live database target `stdlib`. Three
of the four toolchain version shapes Go emits are rejected outright by the `Go` comparer
(measured, table above), so an unnormalized version produces a *skipped* package — loud. The
danger is the opposite: a normalization that parses but orders wrongly, which produces a
clean scan on a vulnerable toolchain and says nothing.

- [ ] **Step 1: Write the failing test — the table is the deliverable**

```go
func TestNormalizeGoVersion(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string
		ok   bool
	}{
		// The ordinary case.
		{"go1.26.4", "1.26.4", true},
		// Go's initial release of a major line had no patch until 1.21.
		// "1.26" is rejected by the comparer outright (measured), so this
		// must gain the .0 or every such toolchain is silently skipped.
		{"go1.20", "1.20.0", true},
		// Release candidates and betas. Go writes them with no separator;
		// semver needs a hyphen and a dot, and the result must sort BELOW
		// the release - 1.21.0-rc.1 < 1.21.0 was measured.
		{"go1.21rc1", "1.21.0-rc.1", true},
		{"go1.22beta1", "1.22.0-beta.1", true},
		{"go1.21.5rc2", "1.21.5-rc.2", true},
		// Already-normalized input passes through: Parse must be safe to
		// call on a version some other code path already cleaned.
		{"1.26.4", "1.26.4", true},
		// Development toolchains name no released version at all. Skipping
		// is right; inventing 1.27.0 would claim a version that does not
		// exist and could be either side of a fix.
		{"devel go1.27-abc123 2026-01-01", "", false},
		{"", "", false},
		{"go", "", false},
		{"gotcha", "", false},
	} {
		got, ok := normalizeGoVersion(tt.in)
		if ok != tt.ok {
			t.Errorf("normalizeGoVersion(%q) ok = %v, want %v", tt.in, ok, tt.ok)
			continue
		}
		if got != tt.want {
			t.Errorf("normalizeGoVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// The normalization exists to be compared, so the test compares. Every
// normalized form must order correctly against the shapes the live stdlib
// advisories actually use (introduced="1.16.0-0", fixed="1.16.1").
func TestNormalizeGoVersion_OrdersAgainstRealAdvisoryBounds(t *testing.T) {
	c, ok := version.For("Go")
	if !ok {
		t.Fatal("no Go comparer")
	}
	for _, tt := range []struct {
		toolchain string
		bound     string
		want      int
	}{
		{"go1.16.0", "1.16.1", -1},   // vulnerable: below the fix
		{"go1.16.1", "1.16.1", 0},    // exactly the fix
		{"go1.16.2", "1.16.1", 1},    // fixed
		{"go1.16", "1.16.0-0", 1},    // the .0 release is above the range's floor
		{"go1.16rc1", "1.16.0-0", 1}, // ...and so is its rc
		{"go1.16rc1", "1.16.0", -1},  // ...but below the release itself
		{"go1.21rc1", "1.21.0", -1},
		{"go1.22beta1", "1.21.0", 1},
	} {
		norm, ok := normalizeGoVersion(tt.toolchain)
		if !ok {
			t.Errorf("normalizeGoVersion(%q) refused a real toolchain version", tt.toolchain)
			continue
		}
		got, err := c.Compare(norm, tt.bound)
		if err != nil {
			t.Errorf("Compare(%q->%q, %q): %v", tt.toolchain, norm, tt.bound, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Compare(%q->%q, %q) = %d, want %d",
				tt.toolchain, norm, tt.bound, got, tt.want)
		}
	}
}

// The package is named exactly "stdlib", because that is the name the 159
// live advisories are filed under. Anything else looks up an empty bucket and
// reports clean - a silent false negative on data already in the database.
func TestParse_AddsTheToolchainAsStdlib(t *testing.T) {
	bin := buildFixture(t, "module example.test/app\n\ngo 1.26\n",
		"package main\n\nfunc main() {}\n")

	tgt, _, err := Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	std := find(t, tgt, "stdlib")
	if std.Ecosystem != "Go" {
		t.Errorf("ecosystem = %q, want Go", std.Ecosystem)
	}
	// The version must be the normalized form, not what buildinfo reported:
	// the comparer rejects the go-prefixed shape outright (measured).
	if strings.HasPrefix(std.Version, "go") {
		t.Errorf("version = %q, still carries the go prefix the comparer rejects", std.Version)
	}
	c, ok := version.For("Go")
	if !ok {
		t.Fatal("no Go comparer")
	}
	if _, err := c.Compare(std.Version, "1.16.1"); err != nil {
		t.Errorf("the reported stdlib version %q does not compare: %v", std.Version, err)
	}
}

// A toolchain version that cannot be normalized - a development build - is a
// COUNTED skip, never a missing package. Dropping it silently would remove
// stdlib from the inventory without removing it from the summary's idea of
// what was evaluated, and an unevaluated stdlib must stay visible.
func TestAddStdlib_AnUnparseableToolchainIsACountedSkip(t *testing.T) {
	// Driven through the seam rather than a built binary, because no
	// toolchain reports a devel version on demand.
	var pkgs []pkgmeta.Package
	var stats cyclonedx.Stats
	addStdlib(&pkgs, &stats, "devel go1.27-abc123 2026-01-01", "/tmp/app")

	for _, p := range pkgs {
		if p.Name == "stdlib" {
			t.Fatalf("an unparseable toolchain was reported as a package: %+v", p)
		}
	}
	if stats.Components != 1 {
		t.Errorf("Components = %d, want 1 - the toolchain was seen", stats.Components)
	}
	if stats.SkippedNoVersion != 1 {
		t.Errorf("SkippedNoVersion = %d, want 1 - the skip must be counted", stats.SkippedNoVersion)
	}
	if stats.Cataloged != 0 {
		t.Errorf("Cataloged = %d, want 0", stats.Cataloged)
	}
}
```

- [ ] **Step 2: Run them, watch them fail**

- [ ] **Step 3: Implement**

Write it as an explicit scan rather than a regexp, and keep it readable against the shapes
above. Handle, in order: reject anything not starting `go` followed by a digit (after
stripping an optional leading `go`); split off a trailing `rc<N>` or `beta<N>` or `alpha<N>`;
pad the numeric core to three components; reassemble as `core[-kind.N]`.

- [ ] **Step 4: Run the tests, watch them pass**

- [ ] **Step 5: Mutation-check before committing**

Each of these must turn the suite red. Apply, confirm, revert:

| Mutation | Why it matters |
|---|---|
| `rc` renders as `1.21.0-rc1` (no dot) | semver reads `rc1` as one identifier; ordering vs `rc.2` changes |
| `rc` renders as `1.21.0+rc.1` (build metadata) | build metadata is ignored in precedence — an rc would equal its release |
| `go1.20` → `1.20` (no padding) | the comparer rejects it; every such toolchain silently skipped |
| the package is named `go` or `golang` instead of `stdlib` | every lookup lands in an empty bucket, reports clean |
| `devel …` normalizes to a version instead of failing | claims a version that does not exist |
| the skip is not counted | an unevaluated stdlib disappears from the summary |

- [ ] **Step 6: Commit**

```bash
git add internal/cataloger/gobinary/
git commit -m "feat: match the Go toolchain as stdlib (D24)"
```

---

### Task 4: The `go.mod` cataloger (D23)

**Files:**
- Create: `internal/cataloger/gomod/gomod.go`, `…/gomod_test.go`

**Interfaces:**
- Produces:
  ```go
  func Parse(dir string) (pkgmeta.Target, cyclonedx.Stats, error)
  ```
  Reads `<dir>/go.mod`. Same package shape as Task 2 — ecosystem `"Go"`, type `"golang"`,
  purl `pkg:golang/<module>@<version>`, `Location{Path: <dir>/go.mod}`.

**What the syntax actually is.** `go.mod` is line-oriented. The parser must handle:

```
module github.com/kun9497/assay        // ignored: the main module has no version here
go 1.26                                 // ignored (D24: a language floor, not a toolchain)
toolchain go1.26.4                      // ignored, for the same reason
require github.com/a/b v1.2.3           // single-line form
require (                               // block form
    github.com/c/d v2.0.0 // indirect   // trailing comment, and the module IS reported
)
exclude github.com/e/f v1.0.0           // ignored
retract v1.0.1                          // ignored
replace github.com/g/h => github.com/i/j v1.5.0   // report i/j at v1.5.0
replace github.com/k/l => ../local                // no version: a counted skip
replace github.com/m/n v1.0.0 => github.com/m/n v1.0.1
```

- [ ] **Step 1: Write the failing tests**

```go
// write drops a go.mod into a fresh directory and returns the directory.
func write(t *testing.T, gomod string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// find resolves a package by EXACT name. Module paths nest, so a
// strings.Contains assertion over the inventory would be satisfied by a
// longer path and pass from the wrong package.
func find(t *testing.T, tgt pkgmeta.Target, name string) pkgmeta.Package {
	t.Helper()
	for _, p := range tgt.Packages {
		if p.Name == name {
			return p
		}
	}
	var have []string
	for _, p := range tgt.Packages {
		have = append(have, p.Name)
	}
	t.Fatalf("no package named %q; got %v", name, have)
	return pkgmeta.Package{}
}

// Both require forms, and the `// indirect` marker kept out of the version.
// An indirect module IS reported: it is linked into the build, and advisories
// apply to it exactly as they do to a direct one.
func TestParse_ReadsBothRequireForms(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\ngo 1.26\n"+
		"\nrequire github.com/single/dep v1.0.0\n"+
		"\nrequire (\n"+
		"\tgithub.com/block/direct v2.3.4\n"+
		"\tgithub.com/block/indirect v0.1.0 // indirect\n"+
		")\n")

	tgt, stats, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.Packages) != 3 {
		t.Fatalf("got %d packages, want 3: %+v", len(tgt.Packages), tgt.Packages)
	}
	for _, tt := range []struct{ name, version string }{
		{"github.com/single/dep", "v1.0.0"},
		{"github.com/block/direct", "v2.3.4"},
		{"github.com/block/indirect", "v0.1.0"},
	} {
		got := find(t, tgt, tt.name)
		if got.Version != tt.version {
			t.Errorf("%s version = %q, want %q", tt.name, got.Version, tt.version)
		}
		if got.Ecosystem != "Go" || got.Type != "golang" {
			t.Errorf("%s = %q/%q, want Go/golang", tt.name, got.Ecosystem, got.Type)
		}
		if want := filepath.Join(dir, "go.mod"); len(got.Locations) != 1 ||
			got.Locations[0].Path != want {
			t.Errorf("%s locations = %+v, want one naming %s", tt.name, got.Locations, want)
		}
	}
	if stats.Cataloged != 3 || stats.Components != 3 {
		t.Errorf("stats = %+v, want 3 cataloged of 3 components", stats)
	}
}

// A replace redirects to a different module, so the reported package is the
// replacement. An advisory against the replaced-away path does not apply to
// code that is not there, and the code that IS there would go unchecked.
func TestParse_FollowsReplace(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/old/mod v1.0.0\n"+
		"\nreplace github.com/old/mod => github.com/new/mod v2.0.0\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt, "github.com/new/mod"); got.Version != "v2.0.0" {
		t.Errorf("version = %q, want v2.0.0", got.Version)
	}
	for _, p := range tgt.Packages {
		if p.Name == "github.com/old/mod" {
			t.Errorf("the replaced-away module is still reported: %+v", p)
		}
	}

	// The version-qualified form replaces only that one version.
	dir2 := write(t, "module example.test/app\n"+
		"\nrequire github.com/m/n v1.0.0\n"+
		"\nreplace github.com/m/n v1.0.0 => github.com/m/n v1.0.1\n")
	tgt2, _, err := Parse(dir2)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt2, "github.com/m/n"); got.Version != "v1.0.1" {
		t.Errorf("version = %q, want v1.0.1", got.Version)
	}
}

// A filesystem replace has no version to compare against any range, so it is
// a COUNTED skip. Reporting it with an empty version leaves the matcher
// undefined; dropping it silently removes a dependency from the inventory
// without removing it from the count of what was evaluated.
func TestParse_AFilesystemReplaceIsACountedSkip(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/k/l v1.0.0\n"+
		"\nreplace github.com/k/l => ../local\n")

	tgt, stats, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.Packages) != 0 {
		t.Errorf("got %+v, want no packages - ../local has no version", tgt.Packages)
	}
	if stats.Components != 1 {
		t.Errorf("Components = %d, want 1 - the module was seen", stats.Components)
	}
	if stats.SkippedNoVersion != 1 {
		t.Errorf("SkippedNoVersion = %d, want 1 - the skip must be counted", stats.SkippedNoVersion)
	}
}

// module, go, toolchain, exclude and retract contribute no packages. Reading
// `go 1.26` as a package named "go" is exactly the mistake D24 names: it
// would report a version nothing was ever built with.
func TestParse_IgnoresNonRequireDirectives(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\ngo 1.26\n"+
		"\ntoolchain go1.26.4\n"+
		"\nexclude github.com/e/f v1.0.0\n"+
		"\nretract v1.0.1\n"+
		"\nrequire github.com/real/dep v1.0.0\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.Packages) != 1 {
		t.Fatalf("got %d packages, want only the require: %+v", len(tgt.Packages), tgt.Packages)
	}
	if tgt.Packages[0].Name != "github.com/real/dep" {
		t.Errorf("package = %q, want github.com/real/dep", tgt.Packages[0].Name)
	}
}

// A go.mod with no require block is a valid module with no dependencies:
// zero packages and no error. This repository had exactly that shape until
// slice 2b, so it is not hypothetical.
func TestParse_ModuleWithNoRequires(t *testing.T) {
	dir := write(t, "module example.test/app\n\ngo 1.26\n")

	tgt, stats, err := Parse(dir)
	if err != nil {
		t.Fatalf("a module with no requires is an error: %v", err)
	}
	if len(tgt.Packages) != 0 {
		t.Errorf("got %+v, want none", tgt.Packages)
	}
	if stats.Components != 0 {
		t.Errorf("Components = %d, want 0", stats.Components)
	}
}

// A directory with no go.mod is an error naming the path, not an empty clean
// scan. "Found nothing" and "there was nothing to look at" must not read
// alike - that distinction is what the whole exit-code contract rests on.
func TestParse_NoGoModIsAnError(t *testing.T) {
	dir := t.TempDir()
	_, _, err := Parse(dir)
	if err == nil {
		t.Fatal("a directory with no go.mod scanned clean")
	}
	if !strings.Contains(err.Error(), "go.mod") {
		t.Errorf("error %q does not mention go.mod", err)
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error %q does not name the directory", err)
	}
}
```

Fixtures are `go.mod` text written into `t.TempDir()`. No toolchain needed.

- [ ] **Step 2: Run them, watch them fail**

- [ ] **Step 3: Implement**

A line scanner with a `inRequireBlock bool`. Strip `//` comments before splitting fields
(but only outside quotes — module paths may be quoted). Two fields in a require line means
`path version`. For `replace`, split on `=>`; the right-hand side's field count decides
whether it is a module (2 fields: path + version) or a filesystem path (1 field).

- [ ] **Step 4: Run the tests, watch them pass**

- [ ] **Step 5: Verify against this repository's own go.mod**

Write a test that parses the repo's real `go.mod` (`../../../go.mod` from the package
directory) and asserts it finds **11** modules with `gotest.tools/v3` among them. That number
is D23's measured claim, and a test that pins it is what keeps the README's limitation
honest.

- [ ] **Step 6: Commit**

```bash
git add internal/cataloger/gomod/
git commit -m "feat: catalog a directory from go.mod, without a toolchain (D23)"
```

---

### Task 5: Wiring, and saying what was read

**Files:**
- Modify: `internal/scancmd/scancmd.go`, `internal/scancmd/scancmd_test.go`
- Modify: `cmd/assay/main.go` (usage text only), `cmd/assay/main_test.go`

**Interfaces:**
- Consumes: `source.Classify`, `gobinary.Parse`, `gomod.Parse` from Tasks 1, 2 and 4.

**The disclosure.** D22 says the classifier's decision is reported so a wrong guess is visible.
D23 says a directory scan states its limitation. Both go to **stderr**, so `--output json`
stays pipeable:

```
scanned ./bin/assay as a go-binary
scanned ./project as a directory: go.mod names 11 module(s); this is what was
  requested, not what a build links - scan the built binary for that
```

The second line prints only for `TargetDirectory`.

- [ ] **Step 1: Write the failing tests**

```go
// Each of the four kinds reaches its own cataloger. A kind routed to the
// wrong parser is the failure D22 exists to prevent, and the error it then
// produces names the wrong problem - a binary handed to the CycloneDX parser
// reports a malformed document.
//
// The assertion is on what each scan FOUND, not on the exit code: every one
// of these exits 0, so an exit-code assertion would pass with all four routed
// to the same parser.
func TestRun_RoutesEachTargetKind(t *testing.T) {
	db := buildMatrixDB(t, nil)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.test/app\n\nrequire github.com/routed/dep v1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5",`+
		`"version":1,"components":[{"type":"library","name":"sbomonly","version":"1.0.0",`+
		`"purl":"pkg:golang/example.com/sbomonly\n1.0.0"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name   string
		target string
		// A package name that appears ONLY when this kind's cataloger ran.
		// Distinct strings with no substring relationship between them, so a
		// row cannot pass from another row's output.
		wantPkg string
	}{
		{"go binary", "file:" + self, "stdlib"},
		{"directory", "dir:" + dir, "github.com/routed/dep"},
		{"sbom", "sbom:" + sbom, "example.com/sbomonly"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), db, tt.target,
				Options{Output: "json"}, &out, &errOut); code != 0 {
				t.Fatalf("Run = %d, want 0; stderr:\n%s", code, errOut.String())
			}
			var doc struct {
				Findings []struct{} `json:"findings"`
				Summary  struct {
					Components int `json:"components"`
				} `json:"summary"`
			}
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("stdout is not one JSON document: %v\n%s", err, out.String())
			}
			if doc.Summary.Components == 0 {
				t.Fatalf("%s produced no components; it was routed to the wrong cataloger\n%s",
					tt.name, out.String())
			}
			// The scan reports how it classified the target, so assert on
			// that too: it is the thing D22 promises is visible.
			if !strings.Contains(errOut.String(), "as a "+tt.name) &&
				!strings.Contains(errOut.String(), "as a go-binary") {
				t.Errorf("stderr does not name the kind:\n%s", errOut.String())
			}
		})
	}
}

// The kind is disclosed, on stderr, so stdout stays a clean document and
// `--output json | jq` is unaffected. A wrong guess must be visible in the
// output rather than inferred from a confusing downstream error.
func TestRun_ReportsHowTheTargetWasClassified(t *testing.T) {
	db := buildMatrixDB(t, nil)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.test/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, dir, Options{}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0; stderr:\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "as a directory") {
		t.Errorf("stderr does not say how the target was classified:\n%s", errOut.String())
	}
	// Not on stdout: that belongs to the report.
	if strings.Contains(out.String(), "as a directory") {
		t.Errorf("the classification went to stdout:\n%s", out.String())
	}
}

// A directory scan says what go.mod is and is not. Without it the 11-of-52
// gap is invisible and a clean directory scan reads as a clean project - the
// silent partial coverage D20 and D21 exist to prevent, arriving through a
// new door.
func TestRun_ADirectoryScanStatesItsLimitation(t *testing.T) {
	db := buildMatrixDB(t, nil)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.test/app\n\nrequire github.com/a/b v1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	Run(context.Background(), db, dir, Options{}, &out, &errOut)
	for _, want := range []string{"go.mod", "not what a build links", "binary"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr missing %q - the limitation is not stated:\n%s", want, errOut.String())
		}
	}
}

// ...and a binary scan does not carry that warning, because it has no such
// gap. A caveat printed on every scan is a caveat readers learn to skip.
func TestRun_ABinaryScanDoesNotWarnAboutGoMod(t *testing.T) {
	db := buildMatrixDB(t, nil)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	Run(context.Background(), db, "file:"+self, Options{}, &out, &errOut)
	if strings.Contains(errOut.String(), "not what a build links") {
		t.Errorf("a binary scan carried the go.mod caveat:\n%s", errOut.String())
	}
	if !strings.Contains(errOut.String(), "as a go-binary") {
		t.Errorf("stderr does not say the target was read as a binary:\n%s", errOut.String())
	}
}

// The gates are the contract, and a new target kind that reaches a different
// verdict path would break them silently. The binary scanned is the test
// binary itself, which links real modules, so the finding is real rather
// than fixture-shaped.
func TestRun_GatesApplyToBinaryAndDirectoryTargets(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// An advisory against a module this test binary genuinely links.
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-binary-hit", pkg: "go.etcd.io/bbolt", fixed: "99.0.0", vectors: []string{vecCritical}},
	})

	none := severity.None
	for _, tt := range []struct {
		name string
		opts Options
		want int
	}{
		{"no flags", Options{}, 0},
		{"--fail-on none trips on a critical finding", Options{FailOn: &none}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if got := Run(context.Background(), db, "file:"+self, tt.opts, &out, &errOut); got != tt.want {
				t.Errorf("Run = %d, want %d; stdout:\n%s\nstderr:\n%s",
					got, tt.want, out.String(), errOut.String())
			}
		})
	}
}
```

- [ ] **Step 2: Run them, watch them fail**

- [ ] **Step 3: Implement**

Replace the `if … == source.TargetImage { … } else { … }` in `Run` with a `switch` over the
four kinds. Keep the existing error-message discipline: no `open %s:` wrapper on errors that
already name the target.

- [ ] **Step 4: Run the tests, watch them pass**

- [ ] **Step 5: Prove the flags survive the trip**

A flag parsed and then dropped between `parseScanArgs` and `scancmd.Run` has happened in this
repo and left the whole suite green. Add a `run()`-seam case using the existing
`buildRunSeamFixture` pattern in `cmd/assay/main_test.go`: a Go binary target with
`--fail-on <band>` reaching exit 1, and the same scan without the flag exiting 0.

- [ ] **Step 6: Commit**

```bash
git add internal/scancmd/ cmd/assay/
git commit -m "feat: scan Go binaries and directories end to end"
```

---

### Task 6: End to end, and the docs

**Do not delegate.** The slice's own claim — "assay scans its own binary" — is checked here,
and the docs record a limitation that has to be stated exactly right.

- [ ] **Step 1: Scan assay's own binary, on the live database**

```bash
export ASSAY_DB_DIR=<the slice 4 scratch database>
go build -o /tmp/assay ./cmd/assay
/tmp/assay scan /tmp/assay
/tmp/assay scan /tmp/assay --output json
/tmp/assay scan dir:.
```

Report the counts and check them against the measured table above: the binary should yield
**12** packages — the main module, 10 linked dependencies, and `stdlib` — while `go.mod`
yields **11**, a different set of a similar size. Report how many findings each produces,
and whether `stdlib` matched anything at the toolchain version in use. Then diff the two
package sets and name every difference; `gotest.tools/v3` should be in the go.mod set and
in neither the binary nor any built artifact, which is D23 visible on real data.

- [ ] **Step 2: Differential against syft and grype**

```bash
syft /tmp/assay -o cyclonedx-json > /tmp/assay.cdx.json
grype /tmp/assay -o json
/tmp/assay scan /tmp/assay.cdx.json
```

Two comparisons: assay-direct vs assay-via-syft's-SBOM (should be identical, and any
divergence is a bug in the new cataloger), and assay vs grype on the same binary (divergence
is expected where data sources differ; a *systematic* difference is not).

- [ ] **Step 3: Mutation-test this slice's claims**

| Mutation | Must fail |
|---|---|
| a bare Go binary classifies as SBOM | Task 1 |
| `file:` prefix ignored | Task 1 |
| an unrecognised file falls through to SBOM | Task 1 |
| `buildinfo` replace directives ignored | Task 2 |
| the main module is dropped | Task 2 |
| `go1.21rc1` normalizes to `1.21.0` (rc discarded) | Task 3 |
| the stdlib package is named `go` | Task 3 |
| `go.mod`'s `go` directive read as a package | Task 4 |
| a filesystem `replace` reported with an empty version | Task 4 |
| a directory target routed to the SBOM parser | Task 5 |
| the directory limitation warning removed | Task 5 |

- [ ] **Step 4: Docs, both languages, same commit**

`README.md` / `README.ko.md`: the two new target forms and the prefixes; the classification
order; and D23's limitation stated as a number, not a hedge — *`go.mod` names what was
requested; on this repository that is 11 modules where the built binary links 10 and the full
module graph holds 52. Scan the binary for what ships.* Move `③` to done in the roadmap
checklist on both sides.

`docs/deferred-decisions.md` / `.ko.md`: SARIF's revisit trigger says "when directory and
binary scanning land — a finding in a checked-out source tree has a real file path". That
trigger has now fired; update the entry to say so rather than leaving a stale condition.

- [ ] **Step 5: Commit**

```bash
git add README.md README.ko.md docs/
git commit -m "docs: filesystem and binary targets"
```

---

## Done when

- `assay scan ./bin/assay` reports the binary's linked modules and its toolchain, and
  `assay scan dir:.` reports `go.mod`'s modules — each visibly labelled as what it is.
- `assay scan ./bin/assay --fail-on high` reaches exit 1 when a high finding is present.
- A binary scan and a scan of syft's SBOM of the same binary agree.
- An unrecognised file is an error naming what was tried, never a JSON parse failure.
- A toolchain version that cannot be normalized is a counted skip, visible in the summary.
- A directory scan states what `go.mod` is and is not, with the measured number.
- No network call and no `go` invocation on any path in this slice.
- Every mutation in Task 6 Step 3 turns the suite red.

## Not in this slice

Java, Rust, or any binary format other than Go (recorded as a deferral — support is decided
per language, not promised as a category). `vendor/` directories. `go.sum`. Reading the module
cache to compute a real build list. npm and PyPI directory scanning.
