# Slice 1: Matching Core — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `assay db update && assay scan sbom.cdx.json` prints real CVEs matched from a local OSV-backed database, for the Go, npm, and PyPI ecosystems.

**Architecture:** A CycloneDX SBOM is parsed into `Target{[]Package}`. Each package is looked up in a bbolt store keyed by `(ecosystem, name)`, which returns advisory IDs; the records are resolved from a `by-id` bucket. A per-ecosystem `Comparer` decides whether the installed version falls inside each advisory's range, and the comparison that decided it is recorded as `Evidence` on the resulting `Finding`.

**Tech Stack:** Go 1.26, `go.etcd.io/bbolt` v1.5.0. No other third-party dependencies — standard library for JSON, zip, and HTTP.

## Global Constraints

- **Go 1.26**, `CGO_ENABLED=0`. Anything requiring cgo is unavailable.
- **Only one new dependency is authorized: `go.etcd.io/bbolt` v1.5.0.** Adding any other requires asking first.
- **The scan path makes no network calls** (D14). Only `assay db update` reaches out.
- **Exit codes are contract** (D11): `0` clean, `1` findings at or above the gate, `2` could not run or cannot be trusted. Precedence `2 > 1 > 0`.
- **Results to stdout, diagnostics to stderr.** `run(args, stdout, stderr) int` stays the testable seam; nothing below `cmd/` touches `os.Stdout` or `os.Exit`.
- **`Comparer.Compare` returns `(int, error)`** (D9). An unparseable version is never silently "not vulnerable".
- **Every path that drops a package must increment a skipped counter that reaches the report.** A dropped comparison is a missed vulnerability.
- **Reference design:** `docs/superpowers/specs/2026-07-29-assay-roadmap.md`. Decisions are cited as D1–D18 throughout.
- Comments explain *why*, not *what*. Match the register of `cmd/assay/main.go`.

---

## File Structure

```
cmd/assay/
  main.go                     MODIFY  add `db` and `scan` command wiring
  main_test.go                MODIFY  extend exit-code table

internal/advisory/
  advisory.go                 Advisory, Affected, Range, Event, Severity, Kind
internal/pkgmeta/
  package.go                  Target, Package, SourcePackage, Location, Distro
  purl.go                     purl -> (ecosystem, name, version)
  purl_test.go
internal/version/
  version.go                  Comparer interface + ecosystem registry
  semver.go                   SemVer 2.0.0 (Go, npm)
  semver_test.go
  pep440.go                   PEP 440 (PyPI)
  pep440_test.go
  rangeeval.go                events -> is this version affected?
  rangeeval_test.go
internal/store/
  store.go                    Store interface, Meta, Provenance
  bolt.go                     bbolt implementation
  bolt_test.go
internal/provider/
  provider.go                 Provider interface
  osv/
    record.go                 OSV JSON record -> []Advisory (D15/D16 filters)
    record_test.go
    fetch.go                  ecosystem zip -> records
internal/cataloger/cyclonedx/
  cyclonedx.go                SBOM JSON -> Target
  cyclonedx_test.go
  testdata/small.cdx.json
internal/matcher/
  matcher.go                  Package x Store -> []Finding with Evidence
  matcher_test.go
internal/report/
  table.go                    findings -> text table + summary
  table_test.go
```

`pkgmeta` rather than `pkg` — a directory named `pkg` collides with a widespread Go layout convention and reads as "miscellaneous", which is what this package must not become.

---

## Task 1: Core types and purl parsing

**Files:**
- Create: `internal/advisory/advisory.go`
- Create: `internal/pkgmeta/package.go`
- Create: `internal/pkgmeta/purl.go`
- Test: `internal/pkgmeta/purl_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `advisory.Advisory`, `advisory.Affected`, `advisory.Range`, `advisory.Event`, `advisory.Severity`, `advisory.Kind` (with `KindVulnerability`, `KindMalicious`), `advisory.RangeType` (with `RangeSemver`, `RangeEcosystem`, `RangeGit`); `pkgmeta.Target`, `pkgmeta.Package`, `pkgmeta.SourcePackage`, `pkgmeta.Location`, `pkgmeta.Distro`; `pkgmeta.ParsePURL(string) (PURL, error)` returning `PURL{Type, Namespace, Name, Version, Qualifiers}`; `pkgmeta.EcosystemForPURLType(string) (string, bool)`.

- [ ] **Step 1: Write the failing test**

```go
package pkgmeta

import "testing"

func TestParsePURL(t *testing.T) {
	cases := []struct {
		in                            string
		typ, namespace, name, version string
	}{
		{"pkg:golang/github.com/foo/bar@v1.2.3", "golang", "github.com/foo", "bar", "v1.2.3"},
		{"pkg:golang/github.com/foo/bar", "golang", "github.com/foo", "bar", ""},
		{"pkg:npm/lodash@4.17.20", "npm", "", "lodash", "4.17.20"},
		{"pkg:npm/%40angular/core@12.0.0", "npm", "@angular", "core", "12.0.0"},
		{"pkg:pypi/django@3.2", "pypi", "", "django", "3.2"},
		{"pkg:apk/alpine/apache2@2.4.54-r0?arch=source", "apk", "alpine", "apache2", "2.4.54-r0"},
		{"pkg:PyPI/Django@3.2", "pypi", "", "Django", "3.2"}, // type lowercases, name does not
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParsePURL(tc.in)
			if err != nil {
				t.Fatalf("ParsePURL(%q) error: %v", tc.in, err)
			}
			if got.Type != tc.typ || got.Namespace != tc.namespace ||
				got.Name != tc.name || got.Version != tc.version {
				t.Errorf("ParsePURL(%q) = %+v, want type=%q ns=%q name=%q ver=%q",
					tc.in, got, tc.typ, tc.namespace, tc.name, tc.version)
			}
		})
	}
}

func TestParsePURL_Qualifiers(t *testing.T) {
	got, err := ParsePURL("pkg:apk/alpine/apache2@2.4.54-r0?arch=source&distro=alpine-3.19")
	if err != nil {
		t.Fatal(err)
	}
	if got.Qualifiers["arch"] != "source" {
		t.Errorf("arch qualifier = %q, want source", got.Qualifiers["arch"])
	}
	if got.Qualifiers["distro"] != "alpine-3.19" {
		t.Errorf("distro qualifier = %q, want alpine-3.19", got.Qualifiers["distro"])
	}
}

func TestParsePURL_Invalid(t *testing.T) {
	for _, in := range []string{"", "golang/foo@v1", "pkg:", "pkg:golang", "pkg:/foo@v1"} {
		if _, err := ParsePURL(in); err == nil {
			t.Errorf("ParsePURL(%q) = nil error, want error", in)
		}
	}
}

func TestEcosystemForPURLType(t *testing.T) {
	cases := map[string]string{"golang": "Go", "npm": "npm", "pypi": "PyPI"}
	for typ, want := range cases {
		got, ok := EcosystemForPURLType(typ)
		if !ok || got != want {
			t.Errorf("EcosystemForPURLType(%q) = %q,%v want %q,true", typ, got, ok, want)
		}
	}
	// apk maps to a distro ecosystem whose key needs a release (D6), which a
	// purl does not carry. Left unmapped rather than mapped to a wrong key.
	if _, ok := EcosystemForPURLType("apk"); ok {
		t.Error("EcosystemForPURLType(apk) = ok, want not ok in slice 1")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/pkgmeta/ -run TestParsePURL -v`
Expected: FAIL — package does not compile, `ParsePURL` undefined.

- [ ] **Step 3: Write the types**

`internal/advisory/advisory.go`:

```go
// Package advisory holds the normalized vulnerability record. The shape follows
// the OSV schema (D1): every provider converts into this rather than the store
// growing a variant per source, which is what makes a KISA provider possible.
package advisory

import "time"

// Kind separates vulnerability reports from malicious-package reports. Only
// KindVulnerability is ingested today (D15), but the field is stored from the
// start because adding one later means rebuilding the database.
type Kind string

const (
	KindVulnerability Kind = "vulnerability"
	KindMalicious     Kind = "malicious"
)

type Advisory struct {
	ID       string     `json:"id"` // CVE-… | GHSA-… | GO-… | ALPINE-… | KVE-…
	Aliases  []string   `json:"aliases,omitempty"`
	Upstream []string   `json:"upstream,omitempty"` // OSV 1.7 puts the CVE link here, not in Aliases (D3)
	Source   string     `json:"source"`             // "osv" | "kisa"
	Kind     Kind       `json:"kind"`
	Summary  string     `json:"summary,omitempty"`
	Modified time.Time  `json:"modified,omitempty"`
	Affected []Affected `json:"affected"`
	Severity []Severity `json:"severity,omitempty"` // CVSS vectors, banded at query time (D13)
}

type Affected struct {
	Ecosystem string   `json:"ecosystem"` // "Go" | "npm" | "PyPI" | "Alpine:v3.19" (D6)
	Name      string   `json:"name"`
	Ranges    []Range  `json:"ranges,omitempty"`
	Versions  []string `json:"versions,omitempty"` // enumerated; the only data when Ranges is empty
}

// RangeType mirrors OSV. GIT ranges carry commit SHAs, not versions, and must
// never reach a Comparer.
type RangeType string

const (
	RangeSemver    RangeType = "SEMVER"
	RangeEcosystem RangeType = "ECOSYSTEM"
	RangeGit       RangeType = "GIT"
)

type Range struct {
	Type   RangeType `json:"type"`
	Events []Event   `json:"events"`
}

// Event carries exactly one populated field. LastAffected is an inclusive upper
// bound; Fixed is exclusive. Conflating them shifts every boundary by one
// version.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type Severity struct {
	Type  string `json:"type"`  // CVSS_V2 | CVSS_V3 | CVSS_V4
	Score string `json:"score"` // the vector string
}
```

`internal/pkgmeta/package.go`:

```go
// Package pkgmeta holds the normalized package inventory: what a scan found,
// independent of where it came from.
package pkgmeta

type Target struct {
	// Distro belongs to the target, not to each package (D7): an image is
	// Alpine 3.19, its packages are not. nil for language-only targets.
	Distro   *Distro
	Packages []Package
}

type Distro struct {
	ID        string // os-release ID, e.g. "alpine"
	VersionID string // os-release VERSION_ID, e.g. "3.19"
}

type Package struct {
	Name      string
	Version   string
	Type      string // purl type: golang | npm | pypi | apk | deb
	Ecosystem string // OSV ecosystem key, resolved at catalog time
	PURL      string
	// Source is the source package an advisory may be keyed on (D8). Distro
	// advisories target source packages while installed packages are binary
	// packages; without this the miss is a false negative, which is silent.
	Source    *SourcePackage
	Locations []Location
}

type SourcePackage struct {
	Name    string
	Version string
}

type Location struct {
	Path        string
	LayerDigest string // empty outside image scans
}
```

`internal/pkgmeta/purl.go`:

```go
package pkgmeta

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type PURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
}

var errNotPURL = errors.New("not a package URL")

// ParsePURL handles the subset of the purl spec that appears in SBOMs:
// pkg:type/namespace/name@version?qualifiers. Subpath (#…) is discarded.
func ParsePURL(s string) (PURL, error) {
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok {
		return PURL{}, fmt.Errorf("parse purl %q: %w", s, errNotPURL)
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}

	var p PURL
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		q, err := url.ParseQuery(rest[i+1:])
		if err != nil {
			return PURL{}, fmt.Errorf("parse purl %q qualifiers: %w", s, err)
		}
		p.Qualifiers = make(map[string]string, len(q))
		for k, v := range q {
			if len(v) > 0 {
				p.Qualifiers[strings.ToLower(k)] = v[0]
			}
		}
		rest = rest[:i]
	}

	typ, path, ok := strings.Cut(rest, "/")
	if !ok || typ == "" || path == "" {
		return PURL{}, fmt.Errorf("parse purl %q: %w", s, errNotPURL)
	}
	// Only the type is case-insensitive. Lowercasing a name would silently
	// fail to match OSV, which is case-sensitive per ecosystem.
	p.Type = strings.ToLower(typ)

	if i := strings.LastIndexByte(path, '@'); i >= 0 {
		v, err := url.PathUnescape(path[i+1:])
		if err != nil {
			return PURL{}, fmt.Errorf("parse purl %q version: %w", s, err)
		}
		p.Version = v
		path = path[:i]
	}

	segs := strings.Split(path, "/")
	for i, seg := range segs {
		d, err := url.PathUnescape(seg)
		if err != nil {
			return PURL{}, fmt.Errorf("parse purl %q segment %d: %w", s, i, err)
		}
		segs[i] = d
	}
	if segs[len(segs)-1] == "" {
		return PURL{}, fmt.Errorf("parse purl %q: empty name", s)
	}
	p.Name = segs[len(segs)-1]
	p.Namespace = strings.Join(segs[:len(segs)-1], "/")
	return p, nil
}

// purlTypeToEcosystem maps purl types to OSV ecosystem keys. Distro types (apk,
// deb, rpm) are absent on purpose: their ecosystem key includes the release
// (D6), which a purl does not carry, so they cannot be resolved here.
var purlTypeToEcosystem = map[string]string{
	"golang": "Go",
	"npm":    "npm",
	"pypi":   "PyPI",
}

func EcosystemForPURLType(typ string) (string, bool) {
	e, ok := purlTypeToEcosystem[strings.ToLower(typ)]
	return e, ok
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/pkgmeta/ -v`
Expected: PASS, all four test functions.

- [ ] **Step 5: Commit**

```bash
git add internal/advisory internal/pkgmeta
git commit -m "feat: add core advisory and package types with purl parsing"
```

---

## Task 2: SemVer comparer

**Files:**
- Create: `internal/version/version.go`
- Create: `internal/version/semver.go`
- Test: `internal/version/semver_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `version.Comparer` interface with `Compare(a, b string) (int, error)`; `version.For(ecosystem string) (Comparer, bool)`; `version.SemVer{}`; sentinel `version.ErrInvalid`.

Rules and every table row below come from SemVer 2.0.0 §2, §9, §10, §11.

- [ ] **Step 1: Write the failing test**

```go
package version

import (
	"errors"
	"testing"
)

var semverTests = []struct {
	a, b string
	want int
}{
	// Version core compares numerically, field by field (§11.2)
	{"1.0.0", "1.0.0", 0},
	{"1.0.0", "2.0.0", -1},
	{"2.0.0", "2.1.0", -1},
	{"2.1.0", "2.1.1", -1},
	{"2.1.1", "2.1.0", 1},
	{"1.0.0", "0.9.9", 1},
	{"0.0.1", "0.1.0", -1},
	{"0.1.0", "1.0.0", -1},
	{"1.9.0", "1.10.0", -1}, // numeric, not lexical
	{"1.0.9", "1.0.10", -1},
	{"2.0.0", "10.0.0", -1},
	{"1.0.0", "18446744073709551616.0.0", -1}, // 2^64: must not overflow
	{"99999999999999999999.1.0", "99999999999999999999.2.0", -1},

	// Pre-release versus normal at equal core (§11.3)
	{"1.0.0-alpha", "1.0.0", -1},
	{"1.0.0", "1.0.0-alpha", 1},
	{"1.0.0-rc.1", "1.0.0", -1},
	{"1.0.0-alpha", "1.0.0-alpha", 0},
	{"1.0.0", "1.0.1-alpha", -1},
	{"1.0.0-alpha", "0.9.9", 1},
	{"2.0.0-alpha", "1.9.9", 1},
	{"0.0.0-experimental-abc", "0.0.0", -1}, // real npm shape

	// The spec's own example chain (§11.4)
	{"1.0.0-alpha", "1.0.0-alpha.1", -1},
	{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
	{"1.0.0-alpha.beta", "1.0.0-beta", -1},
	{"1.0.0-beta", "1.0.0-beta.2", -1},
	{"1.0.0-beta.2", "1.0.0-beta.11", -1},
	{"1.0.0-beta.11", "1.0.0-rc.1", -1},
	{"1.0.0-rc.1", "1.0.0", -1},
	{"1.0.0-alpha", "1.0.0-rc.1", -1},

	// Numeric identifiers, numeric versus non-numeric (§11.4.1, §11.4.3)
	{"1.0.0-1", "1.0.0-2", -1},
	{"1.0.0-2", "1.0.0-10", -1},
	{"1.0.0-0", "1.0.0-1", -1},
	{"1.0.0-0", "1.0.0-0", 0},
	{"1.0.0-alpha.2", "1.0.0-alpha.10", -1},
	{"1.0.0-1", "1.0.0-alpha", -1},
	{"1.0.0-999999", "1.0.0-a", -1}, // magnitude never beats "non-numeric is higher"
	{"1.0.0-alpha.1", "1.0.0-alpha.a", -1},
	{"1.0.0-alpha.1", "1.0.0-alpha.0valid", -1},
	{"1.0.0-alpha.1", "1.0.0-alpha.01a", -1},
	{"1.0.0-18446744073709551616", "1.0.0-18446744073709551617", -1},

	// ASCII lexical order for non-numeric identifiers (§11.4.2)
	{"1.0.0-alpha", "1.0.0-beta", -1},
	{"1.0.0-alpha", "1.0.0-rc", -1},
	{"1.0.0-Alpha", "1.0.0-alpha", -1},    // case is significant
	{"1.0.0-RC.1", "1.0.0-alpha", -1},     // uppercase sorts below lowercase
	{"1.0.0-alpha10", "1.0.0-alpha9", -1}, // one identifier: string compare
	{"1.0.0-rc2", "1.0.0-rc10", 1},
	{"1.0.0-a", "1.0.0-a-", -1},
	{"1.0.0-alpha.1", "1.0.0-alpha-1", -1}, // b is a single field "alpha-1"
	{"1.0.0-x-y-z.--", "1.0.0-x-y-z.-a", -1},
	{"1.0.0-0", "1.0.0--", -1}, // §11.4.3 overrides ASCII order

	// Running out of fields (§11.4.4)
	{"1.0.0-alpha", "1.0.0-alpha.0", -1},
	{"1.0.0-1", "1.0.0-1.0", -1},
	{"1.0.0-alpha.1", "1.0.0-alpha.1.0", -1},
	{"1.0.0-alpha.beta", "1.0.0-alpha", 1},
	{"1.0.0-a.b.c", "1.0.0-a.b", 1},
	{"1.0.0-b", "1.0.0-a.b.c.d", 1},
	{"0.0.0-0", "0.0.0-0.0", -1},
	{"0.0.0-0", "0.0.0", -1}, // global minimum valid semver

	// Build metadata is ignored for precedence (§10, §11.1)
	{"1.0.0", "1.0.0+build.1", 0},
	{"1.0.0+build.1", "1.0.0+build.2", 0},
	{"1.0.0+build.2", "1.0.0+build.1", 0},
	{"1.0.0+001", "1.0.0+999", 0},
	{"1.0.0-alpha+001", "1.0.0-alpha", 0},
	{"1.0.0-alpha+001", "1.0.0+001", -1},
	{"1.0.0+20130313144700", "1.0.0-beta+exp.sha.5114f85", 1},
	{"1.0.0+21AF26D3----117B344092BD", "1.0.0", 0},
	{"1.0.0+build", "1.0.0-alpha+build", 1},

	// Go module versions: leading v, +incompatible, pseudo-versions
	{"v1.0.0", "1.0.0", 0},
	{"v1.0.0", "v1.0.1", -1},
	{"1.0.0", "v1.0.1", -1}, // bare OSV bound versus v-prefixed artifact
	{"v1.0.0-alpha", "1.0.0", -1},
	{"v2.0.0+incompatible", "v2.0.0", 0},
	{"v2.0.0+incompatible", "2.0.0", 0},
	{"v0.0.0-20191109021931-daa7c04131f5", "v0.0.0-20200114041708-b6a2b0a5b8b5", -1},
	{"v0.0.0-20191109021931-daa7c04131f5", "v0.0.1", -1},
	{"v1.2.3-0.20191109021931-daa7c04131f5", "v1.2.3", -1},
	{"v1.2.2", "v1.2.3-0.20191109021931-daa7c04131f5", -1},
	{"v1.2.3-0.20191109021931-daa7c04131f5", "v1.2.3-alpha", -1},
}

func TestSemVerCompare(t *testing.T) {
	var c SemVer
	for _, tc := range semverTests {
		got, err := c.Compare(tc.a, tc.b)
		if err != nil {
			t.Errorf("Compare(%q, %q) error: %v", tc.a, tc.b, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		// Antisymmetry is cheap to assert and catches whole classes of bug
		// that individual rows miss.
		rev, err := c.Compare(tc.b, tc.a)
		if err != nil {
			t.Errorf("Compare(%q, %q) error: %v", tc.b, tc.a, err)
			continue
		}
		if rev != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, rev, -tc.want)
		}
	}
}

func TestSemVerInvalid(t *testing.T) {
	invalid := []string{
		"", "1", "1.0", "1.0.0.0", "v1.0.0.0",
		"01.0.0", "1.01.0", "1.0.01", "-1.0.0",
		"1.0.0-01", "1.0.0-alpha.00", "1.0.0-", "1.0.0-alpha..1",
		"1.0.0-.alpha", "1.0.0-alpha.", "1.0.0-alpha_beta", "1.0.0-α",
		"1.0.0-beta*", "1.0.0-a b", "1.0.0+", "1.0.0+build..1",
		"1.0.0+build_1", "1.0.0+build+more", "1.0.0-+build",
		" 1.0.0", "1.0.0 ", "1.2.x", "^1.2.3", "~1.2.3", ">=1.2.3", "*",
		"latest", "V1.0.0", "vv1.0.0",
		// The OSV sentinel is not a version. The range layer resolves it to
		// negative infinity before Compare is called; coercing it to 0.0.0
		// here would silently exclude every 0.0.0-prerelease build.
		"0",
	}
	for _, in := range invalid {
		if _, err := (SemVer{}).Compare(in, "1.0.0"); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(%q, …) err = %v, want ErrInvalid", in, err)
		}
	}
}

func TestSemVerValidButUnusual(t *testing.T) {
	valid := []string{
		"1.0.0-0.3.7", "1.0.0-x.7.z.92", "1.0.0-x-y-z.--",
		"1.0.0-alpha+001", "1.0.0+21AF26D3----117B344092BD",
		"1.0.0-beta+exp.sha.5114f85", "1.0.0--", "1.0.0---",
		"1.0.0-0", "1.0.0+001", "1.0.0-01a", "1.0.0-0valid",
		"0.0.0", "0.0.0-0", "99999999999999999999.0.0",
		"v2.0.0+incompatible", "v0.0.0-20191109021931-daa7c04131f5",
	}
	for _, in := range valid {
		if _, err := (SemVer{}).Compare(in, "1.0.0"); err != nil {
			t.Errorf("Compare(%q, …) err = %v, want nil", in, err)
		}
	}
}

func TestForEcosystem(t *testing.T) {
	for _, eco := range []string{"Go", "npm"} {
		c, ok := For(eco)
		if !ok {
			t.Fatalf("For(%q) not registered", eco)
		}
		if _, ok := c.(SemVer); !ok {
			t.Errorf("For(%q) = %T, want SemVer", eco, c)
		}
	}
	if _, ok := For("Nonesuch"); ok {
		t.Error("For(Nonesuch) = ok, want not ok")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/version/ -run TestSemVer -v`
Expected: FAIL — `SemVer` and `ErrInvalid` undefined.

- [ ] **Step 3: Write the implementation**

`internal/version/version.go`:

```go
// Package version implements per-ecosystem version ordering.
//
// There is deliberately no shared compareVersions (D9). Debian epochs, RPM
// release ordering, semver pre-release precedence, and PEP 440 all disagree,
// and a single function that tries to serve them is the bug this design avoids.
package version

import "errors"

// ErrInvalid marks a version string that cannot be ordered. Callers must treat
// it as "unknown", never as "not vulnerable" — a swallowed error here is a
// missed vulnerability.
var ErrInvalid = errors.New("invalid version")

type Comparer interface {
	// Compare returns -1, 0, or 1. It returns an error wrapping ErrInvalid
	// rather than guessing an ordering for input it cannot parse.
	Compare(a, b string) (int, error)
}

var registry = map[string]Comparer{
	"Go":   SemVer{},
	"npm":  SemVer{},
	"PyPI": PEP440{},
}

func For(ecosystem string) (Comparer, bool) {
	c, ok := registry[ecosystem]
	return c, ok
}
```

`internal/version/semver.go`:

```go
package version

import (
	"fmt"
	"strings"
)

// maxVersionLen bounds work on hostile advisory or SBOM input. Not a spec rule.
const maxVersionLen = 256

type SemVer struct{}

type semverParsed struct {
	core [3]string // numeric identifiers, leading zeros already rejected
	pre  []string  // nil when absent
}

func (SemVer) Compare(a, b string) (int, error) {
	pa, err := parseSemVer(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseSemVer(b)
	if err != nil {
		return 0, err
	}
	for i := range 3 {
		if c := compareNumeric(pa.core[i], pb.core[i]); c != 0 {
			return c, nil
		}
	}
	// A version without a pre-release outranks one with it (§11.3). This pulls
	// the opposite way from the "more fields wins" rule below; conflating the
	// two is the classic semver bug.
	switch {
	case pa.pre == nil && pb.pre == nil:
		return 0, nil
	case pa.pre == nil:
		return 1, nil
	case pb.pre == nil:
		return -1, nil
	}
	for i := 0; i < len(pa.pre) && i < len(pb.pre); i++ {
		x, y := pa.pre[i], pb.pre[i]
		nx, ny := isNumericID(x), isNumericID(y)
		switch {
		case nx && ny:
			if c := compareNumeric(x, y); c != 0 {
				return c, nil
			}
		case !nx && !ny:
			if c := strings.Compare(x, y); c != 0 {
				return c, nil
			}
		case nx: // numeric identifiers rank below alphanumeric ones (§11.4.3)
			return -1, nil
		default:
			return 1, nil
		}
	}
	// All shared fields equal: more fields wins (§11.4.4).
	switch {
	case len(pa.pre) < len(pb.pre):
		return -1, nil
	case len(pa.pre) > len(pb.pre):
		return 1, nil
	}
	return 0, nil
}

func parseSemVer(s string) (semverParsed, error) {
	var p semverParsed
	if s == "" || len(s) > maxVersionLen {
		return p, fmt.Errorf("semver %q: %w", s, ErrInvalid)
	}
	// Strip exactly one lowercase v, at position 0 only. OSV SEMVER bounds
	// carry no prefix while Go artifacts do, so both operands must be
	// normalized — normalizing one side sends every Go comparison to the
	// error path.
	s = strings.TrimPrefix(s, "v")

	// Build metadata is discarded before comparison, not used as a tiebreaker
	// (§10). It must still be syntactically valid.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if err := validIdentifiers(s[i+1:], true); err != nil {
			return p, fmt.Errorf("semver %q build metadata: %w", s, ErrInvalid)
		}
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre := s[i+1:]
		if err := validIdentifiers(pre, false); err != nil {
			return p, fmt.Errorf("semver %q pre-release: %w", s, ErrInvalid)
		}
		p.pre = strings.Split(pre, ".")
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return p, fmt.Errorf("semver %q: core needs exactly three identifiers: %w", s, ErrInvalid)
	}
	for i, part := range parts {
		if !isNumericID(part) || hasLeadingZero(part) {
			return p, fmt.Errorf("semver %q core identifier %q: %w", s, part, ErrInvalid)
		}
		p.core[i] = part
	}
	return p, nil
}

// validIdentifiers checks a dot-separated identifier list. build allows leading
// zeros on numeric-looking identifiers; pre-release does not (§10 versus §9).
func validIdentifiers(s string, build bool) error {
	if s == "" {
		return ErrInvalid
	}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return ErrInvalid
		}
		for i := 0; i < len(id); i++ {
			c := id[i]
			ok := c == '-' || (c >= '0' && c <= '9') ||
				(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			if !ok {
				return ErrInvalid
			}
		}
		if !build && isNumericID(id) && hasLeadingZero(id) {
			return ErrInvalid
		}
	}
	return nil
}

func isNumericID(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func hasLeadingZero(s string) bool { return len(s) > 1 && s[0] == '0' }

// compareNumeric orders two digit strings without parsing them into a fixed
// width. The spec sets no upper bound on numeric identifiers, so strconv would
// be a conformance bug on real input.
func compareNumeric(a, b string) int {
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return strings.Compare(a, b)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/version/ -run 'TestSemVer|TestFor' -v`
Expected: PASS.

The registry in `version.go` references `PEP440`, which Task 3 creates. To keep this task compiling on its own, add this stub to `version.go` now and let Task 3 replace it with the real file:

```go
// Replaced in Task 3.
type PEP440 struct{}

func (PEP440) Compare(a, b string) (int, error) { return 0, ErrInvalid }
```

- [ ] **Step 5: Commit**

```bash
git add internal/version/version.go internal/version/semver.go internal/version/semver_test.go
git commit -m "feat: add SemVer 2.0.0 comparer with ecosystem registry"
```

---

## Task 3: PEP 440 comparer

**Files:**
- Create: `internal/version/pep440.go`
- Modify: `internal/version/version.go` — delete the `PEP440` stub from Task 2
- Test: `internal/version/pep440_test.go`

**Interfaces:**
- Consumes: `version.ErrInvalid`, `version.Comparer`, `compareNumeric`, `isNumericID` from Task 2.
- Produces: `version.PEP440{}` implementing `Comparer`.

Every row of the table below was executed against `packaging` 26.2 and a from-scratch Go implementation: 165/165 agreement. Do not "fix" a row that looks wrong — re-derive it from the cited PEP 440 section first.

Two Go-specific traps, both confirmed empirically:

1. **Do not use `(?i)` in the regex.** Go's case-insensitive flag performs Unicode folding, so `[a-z]` matches U+212A KELVIN SIGN and U+017F LONG S. Python guards against this with `(?a:)`, which Go lacks. Reject non-ASCII input up front, ASCII-lowercase the string yourself, and compile without `(?i)`.
2. **Numeric components are unbounded.** Epoch, release, pre/post/dev numbers, and numeric local segments are arbitrary precision in Python. Reuse `compareNumeric` from Task 2 rather than `strconv.Atoi`.

- [ ] **Step 1: Write the failing test**

```go
package version

import (
	"errors"
	"testing"
)

var pep440Tests = []struct {
	a, b string
	want int
}{
	// Epoch
	{"1.0", "1!1.0", -1},
	{"1!1.0", "1.0", 1},
	{"2!1.0", "1!2.0", 1},
	{"1!0.1", "9999999", 1},
	{"1!0", "0!99999", 1},
	{"0!1.0", "1.0", 0},
	{"01!1.0", "1!1.0", 0},
	{"1!1.0", "1!1.0.0", 0},
	{"1!1.0.dev1", "1.0", 1},

	// Release segment: length, trailing zeros, numeric compare
	{"1.0", "1.0.0", 0},
	{"1", "1.0.0.0", 0},
	{"1.0", "1.0.0.0.0.0.0.0.0.0", 0},
	{"1.0", "1.0.1", -1},
	{"1.0.0.1", "1.0.1", -1},
	{"1.0.0.0.0.0.1", "1.0.1", -1},
	{"1.0.1", "1.1", -1},
	{"1.10", "1.9", 1},
	{"1.0.15", "1.0.2", 1},
	{"10.0", "9.0", 1},
	{"2", "1.999999", 1},
	{"1.0.0.0.0.0.0.1", "1.0.0.0.0.0.0.2", -1},
	{"0", "0.0", 0},
	{"0", "0.0.1", -1},
	{"99999999999999999999999999.0", "100000000000000000000000000.0", -1},

	// Leading zeros
	{"1.01", "1.1", 0},
	{"01.0", "1.0", 0},
	{"1.0.00", "1", 0},
	{"1.0a01", "1.0a1", 0},
	{"1.0.post01", "1.0.post1", 0},
	{"1.0.dev01", "1.0.dev1", 0},
	{"1.0+001", "1.0+1", 0},           // numeric local segment IS normalized
	{"1.0+foo0100", "1.0+foo100", -1}, // alphanumeric local segment is NOT

	// v prefix, whitespace, case folding
	{"v1.0", "1.0", 0},
	{"V1.0", "1.0", 0},
	{"  1.0  ", "1.0", 0},
	{"\t1.0\n", "1.0", 0},
	{"1.0A1", "1.0a1", 0},
	{"1.0RC1", "1.0rc1", 0},
	{"1.0.POST1", "1.0.post1", 0},
	{"1.0.DEV1", "1.0.dev1", 0},
	{"1.0+ABC", "1.0+abc", 0},
	{"v1!1.0.post1.dev2+ABC.1", "1!1.0.post1.dev2+abc.1", 0},
	{"1!2.0.0a1.post2.dev3+ubuntu.1", "v1!2.0.0.alpha.1-post-2_dev3+UBUNTU-1", 0},

	// Pre-release spelling equivalences
	{"1.0alpha1", "1.0a1", 0},
	{"1.0beta2", "1.0b2", 0},
	{"1.0c1", "1.0rc1", 0},
	{"1.0pre1", "1.0rc1", 0},
	{"1.0preview1", "1.0rc1", 0},
	{"1.0.0rc1", "1.0.0c1", 0},
	{"1.0-alpha-1", "1.0a1", 0},
	{"1.0_beta_2", "1.0b2", 0},
	{"1.0.rc.1", "1.0rc1", 0},
	{"1.0.0-rc.1", "1.0.0rc1", 0}, // semver-shaped input is legal PEP 440
	{"1.0.0-beta.1", "1.0.0b1", 0},

	// Implicit pre-release number
	{"1.0a", "1.0a0", 0},
	{"1.0b", "1.0b0", 0},
	{"1.0rc", "1.0rc0", 0},
	{"1.0alpha", "1.0a0", 0},
	{"1.0a", "1.0a1", -1},

	// Pre-release ordering
	{"1.0a1", "1.0a2", -1},
	{"1.0a2", "1.0a10", -1},
	{"1.0a10", "1.0b1", -1},
	{"1.0b1", "1.0rc1", -1},
	{"1.0b2", "1.0c1", -1},
	{"1.0rc1", "1.0", -1},
	{"1.0a1", "0.9", 1},

	// Post-release spellings and implicit forms
	{"1.0.post1", "1.0-post1", 0},
	{"1.0.post1", "1.0post1", 0},
	{"1.0.post1", "1.0_post_1", 0},
	{"1.0.post1", "1.0-1", 0}, // implicit post release
	{"1-0", "1.post0", 0},
	{"1.0.rev1", "1.0.post1", 0},
	{"1.0.r1", "1.0.post1", 0},
	{"1.0.post", "1.0.post0", 0},
	{"1.0-r", "1.0.post0", 0},
	{"1.0-0", "1.0.post0", 0},

	// Post-release ordering
	{"1.0", "1.0.post0", -1}, // .post0 is GREATER than no post at all
	{"1.0.post1", "1.0.post2", -1},
	{"1.0.post2", "1.0.post10", -1},
	{"1.0.post1", "1.0.1", -1}, // post never escapes its release
	{"1.0.post1", "1.1", -1},
	{"1.0.post1", "1.0rc1", 1},

	// Dev releases
	{"1.0.dev1", "1.0", -1},
	{"1.0.dev1", "1.0a1", -1}, // dev-only sorts before ALL pre-releases
	{"1.0.dev0", "1.0a0.dev0", -1},
	{"1.0a1.dev1", "1.0.dev1", 1},
	{"1.0.dev", "1.0.dev0", 0},
	{"1.0dev1", "1.0.dev1", 0},
	{"1.0-dev1", "1.0.dev1", 0},
	{"1.0_dev_1", "1.0.dev1", 0},
	{"1.0.0-dev-1", "1.0.0.dev1", 0},
	{"1.0.dev1", "1.0.dev2", -1},
	{"1.0.dev2", "1.0.dev10", -1},
	{"1.0a1.dev1", "1.0a1", -1},
	{"1.0a1.dev1", "1.0a1.dev2", -1},
	{"1.0.dev1", "0.9.9", 1},
	{"1.dev0", "1.0.dev456", -1},
	{"1.0.dev0", "1.0.0.dev0", 0},

	// Dev release OF a post release: sorts AFTER the base version
	{"1.0.post1.dev1", "1.0", 1}, // counterintuitive, most-missed rule
	{"1.0.post1.dev1", "1.0.post1", -1},
	{"1.0.post1.dev1", "1.0.dev1", 1},
	{"1.0.post0.dev0", "1.0", 1},
	{"1.0.dev0", "1.0.post0.dev0", -1},
	{"1.0.post1.dev0", "1.0.post0", 1},
	{"2.0", "2.0.post0.dev0", -1},

	// Pre + post + dev combinations
	{"1.0a1.post1", "1.0a1", 1},
	{"1.0a1.post1", "1.0b1", -1},
	{"1.0a1.post2", "1.0a2", -1}, // pre number outranks post
	{"1.0a1.post1.dev1", "1.0a1.post1", -1},
	{"1.0a1.post1.dev1", "1.0a1", 1},
	{"1.0a1.post1", "1.0a1.post1.dev999", 1},
	{"1.0b2.post345.dev456", "1.0b2.post345", -1},
	{"1.0rc1.dev1", "1.0b1", 1},
	{"1.2.3.4rc1.post2.dev3", "1.2.3.4rc1.post2", -1},

	// Local versions
	{"1.0", "1.0+abc", -1},
	{"1.0", "1.0+0", -1},
	{"1.0.0+build.1", "1.0.0", 1},
	{"1!1.0+local", "1!1.0", 1},
	{"1.0.post1+local", "1.0.post1", 1},
	{"1.0+abc.5", "1.0+abc.7", -1},
	{"1.0+2", "1.0+10", -1},
	{"1.0+abc", "1.0+abd", -1},
	{"1.0+abc.7", "1.0+5", -1}, // numeric segment > alphanumeric segment
	{"1.0+5", "1.0+abc", 1},
	{"1.0+0", "1.0+a", 1},
	{"1.0+1.a", "1.0+1.1", -1},
	{"1.0+foo", "1.0+foo.0", -1}, // shorter prefix first; NO trailing-zero trim
	{"1.0+1", "1.0+1.0", -1},
	{"1.0+abc", "1.0+abc.0", -1},
	{"1.0+abc.1", "1.0+abc.1.0", -1},
	{"1.0+a.1", "1.0+a.1.b", -1},
	{"1.0+ubuntu-1", "1.0+ubuntu.1", 0},
	{"1.0+ubuntu_1", "1.0+ubuntu.1", 0},
	{"1.0+abc", "1.0+ABC", 0},
	{"1.0.0+abc", "1.0+abc", 0},
	{"1.0+deadbeef", "1.0.1", -1},
	{"1.0+local", "1.0.post1", -1},
	{"1.0+99999999999999999999", "1.0+100000000000000000000", -1},

	// "0" is NOT the minimum PEP 440 version — same trap as semver
	{"0", "1.0", -1},
	{"0", "0.dev0", 1},
	{"0", "0a1", 1},
	{"0", "0.0.0rc1", 1},

	// Reflexivity
	{"1.0", "1.0", 0},
	{"1!2.0.0a1.post2.dev3+ubuntu.1", "1!2.0.0a1.post2.dev3+ubuntu.1", 0},

	// The canonical ordering example from PEP 440, as adjacent pairs
	{"1.dev0", "1.0.dev456", -1},
	{"1.0.dev456", "1.0a1", -1},
	{"1.0a1", "1.0a2.dev456", -1},
	{"1.0a2.dev456", "1.0a12.dev456", -1},
	{"1.0a12.dev456", "1.0a12", -1},
	{"1.0a12", "1.0b1.dev456", -1},
	{"1.0b1.dev456", "1.0b2", -1},
	{"1.0b2", "1.0b2.post345.dev456", -1},
	{"1.0b2.post345.dev456", "1.0b2.post345", -1},
	{"1.0b2.post345", "1.0rc1.dev456", -1},
	{"1.0rc1.dev456", "1.0rc1", -1},
	{"1.0rc1", "1.0", -1},
	{"1.0", "1.0+abc.5", -1},
	{"1.0+abc.5", "1.0+abc.7", -1},
	{"1.0+abc.7", "1.0+5", -1},
	{"1.0+5", "1.0.post456.dev34", -1},
	{"1.0.post456.dev34", "1.0.post456", -1},
	{"1.0.post456", "1.0.15", -1},
	{"1.0.15", "1.1.dev1", -1},
}

func TestPEP440Compare(t *testing.T) {
	var c PEP440
	for _, tc := range pep440Tests {
		got, err := c.Compare(tc.a, tc.b)
		if err != nil {
			t.Errorf("Compare(%q, %q) error: %v", tc.a, tc.b, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		rev, err := c.Compare(tc.b, tc.a)
		if err != nil {
			t.Errorf("Compare(%q, %q) error: %v", tc.b, tc.a, err)
			continue
		}
		if rev != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, rev, -tc.want)
		}
	}
}

func TestPEP440Invalid(t *testing.T) {
	invalid := []string{
		// Structurally malformed
		"", "   ", "1.", "1.0.0.", ".1.0", "1..0", "-1.0", "+1.0",
		"1!", "!1.0", "1!2!3.0", "vv1.0", "x1.0", "latest", "None",
		"*", "1.0.*", "1.0 beta", "1 . 0",
		// Segment misuse
		"1.0_1", "1.0.0_1", // implicit post release requires "-" specifically
		"1.0.0-1.2", "1.0.dev1.post2", "1.0.post1.pre2",
		"3.0.0.rc1.dev1.post2", "1.0a1b2", "1.0.0rc1.rc2",
		"1.0.post1.post2", "1.0.0.dev1.dev2",
		"1.0.0-alpha.beta", "1.0.0a-b", "1.0a.1.2", "1.0K", "2011k",
		// Local-version malformed
		"1.0+", "1.0+.", "1.0+abc.", "1.0.0+abc-", "1.0+abc..1",
		"1.0.0++abc", "1.0+abc+def", "1.0.0+local!", "1.0.0+lo cal",
		// Non-ASCII: Go's (?i) would fold these into ASCII if not rejected first.
		// The third entry is U+212A KELVIN SIGN, which Go's Unicode case folding
		// maps onto lowercase ASCII "k" — so an unguarded (?i) regex would accept
		// it as a valid local version. It is written as an escape, and named here
		// rather than shown, because a literal character on either line gets
		// flattened to plain ASCII by editors and tooling. When that happens the
		// row silently starts asserting that a perfectly valid version is invalid,
		// and the comment explaining why stops being true. The escape cannot flatten.
		"１.０", "٣.٤", "1.0+\u212a",
		// Legacy PyPI shapes that cannot be ordered at all
		"1.0dev-r1234", "1.0.0-SNAPSHOT", "linux-2.6",
		// OSV sentinel, as in semver
		"0!",
	}
	for _, in := range invalid {
		if _, err := (PEP440{}).Compare(in, "1.0"); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(%q, …) err = %v, want ErrInvalid", in, err)
		}
	}
}

func TestPEP440LegacyLookingButValid(t *testing.T) {
	// These look legacy but do parse, and rejecting them would drop real
	// advisories on the floor.
	valid := map[string]string{
		"0.9.9a-1":   "0.9.9a1",
		"1.0.0-rc.1": "1.0.0rc1",
		"2.0-r":      "2.0.post0",
		"1-0":        "1.post0",
	}
	for in, equiv := range valid {
		got, err := (PEP440{}).Compare(in, equiv)
		if err != nil {
			t.Errorf("Compare(%q, %q) err = %v, want nil", in, equiv, err)
			continue
		}
		if got != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", in, equiv, got)
		}
	}
}

func TestPEP440RegisteredForPyPI(t *testing.T) {
	c, ok := For("PyPI")
	if !ok {
		t.Fatal("For(PyPI) not registered")
	}
	if _, ok := c.(PEP440); !ok {
		t.Errorf("For(PyPI) = %T, want PEP440", c)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/version/ -run TestPEP440 -v`
Expected: FAIL — the Task 2 stub returns `ErrInvalid` for everything, so `TestPEP440Compare` fails on the first row.

- [ ] **Step 3: Write the implementation**

Delete the `PEP440` stub from `version.go`, then create `internal/version/pep440.go`:

```go
package version

import (
	"fmt"
	"regexp"
	"strings"
)

type PEP440 struct{}

// pep440Pattern is the reference grammar from PEP 440's appendix, translated
// for RE2: possessive quantifiers dropped (a CPython performance detail with no
// semantic effect) and (?a:) dropped (Go has no equivalent).
//
// Deliberately NOT compiled with (?i). Go's case-insensitive flag folds
// Unicode, so [a-z] would match U+212A KELVIN SIGN — accepting input the
// reference implementation rejects. Input is ASCII-checked and lowercased by
// the caller instead.
var pep440Pattern = regexp.MustCompile(`\A` +
	`v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[._-]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[._-]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[._-]?(?P<post_l>post|rev|r)[._-]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[._-]?(?P<dev_l>dev)[._-]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[._-][a-z0-9]+)*))?` +
	`\z`)

// pep440Key is the comparison key. Field order is the comparison order.
type pep440Key struct {
	epoch   string   // digit string
	release []string // trailing zeros already stripped
	preRank int      // -1 dev-only, 0 a, 1 b, 2 rc, 3 none
	preN    string
	postRank int // 0 absent, 1 present
	postN    string
	devRank  int // 0 present, 1 absent
	devN     string
	hasLocal bool
	local    []string
}

func (PEP440) Compare(a, b string) (int, error) {
	ka, err := parsePEP440(a)
	if err != nil {
		return 0, err
	}
	kb, err := parsePEP440(b)
	if err != nil {
		return 0, err
	}
	if c := compareNumeric(ka.epoch, kb.epoch); c != 0 {
		return c, nil
	}
	// Release components compare numerically; when one is a prefix of the
	// other the shorter is smaller. Trailing zeros were stripped at parse
	// time, which is what makes 1.0 == 1.0.0 == 1.
	for i := 0; i < len(ka.release) && i < len(kb.release); i++ {
		if c := compareNumeric(ka.release[i], kb.release[i]); c != 0 {
			return c, nil
		}
	}
	if c := cmpInt(len(ka.release), len(kb.release)); c != 0 {
		return c, nil
	}
	if c := cmpInt(ka.preRank, kb.preRank); c != 0 {
		return c, nil
	}
	if c := compareNumeric(ka.preN, kb.preN); c != 0 {
		return c, nil
	}
	if c := cmpInt(ka.postRank, kb.postRank); c != 0 {
		return c, nil
	}
	if c := compareNumeric(ka.postN, kb.postN); c != 0 {
		return c, nil
	}
	if c := cmpInt(ka.devRank, kb.devRank); c != 0 {
		return c, nil
	}
	if c := compareNumeric(ka.devN, kb.devN); c != 0 {
		return c, nil
	}
	// A version carrying a local label outranks the same version without one.
	if ka.hasLocal != kb.hasLocal {
		if kb.hasLocal {
			return -1, nil
		}
		return 1, nil
	}
	for i := 0; i < len(ka.local) && i < len(kb.local); i++ {
		x, y := ka.local[i], kb.local[i]
		nx, ny := isNumericID(x), isNumericID(y)
		switch {
		case nx && ny:
			if c := compareNumeric(x, y); c != 0 {
				return c, nil
			}
		case !nx && !ny:
			if c := strings.Compare(x, y); c != 0 {
				return c, nil
			}
		case nx: // a numeric segment always outranks an alphanumeric one
			return 1, nil
		default:
			return -1, nil
		}
	}
	// Unlike the release segment, local labels are not trailing-zero trimmed:
	// the shorter prefix sorts first.
	return cmpInt(len(ka.local), len(kb.local)), nil
}

func parsePEP440(s string) (pep440Key, error) {
	var k pep440Key
	if len(s) > maxVersionLen {
		return k, fmt.Errorf("pep440 %q: %w", s, ErrInvalid)
	}
	// Only ASCII whitespace is stripped. Python's \s also matches U+00A0 and
	// friends; being stricter here is the safe direction.
	t := strings.Trim(s, " \t\n\r\f\v")
	for i := 0; i < len(t); i++ {
		if t[i] >= 0x80 {
			return k, fmt.Errorf("pep440 %q: non-ASCII: %w", s, ErrInvalid)
		}
	}
	t = strings.ToLower(t)

	m := pep440Pattern.FindStringSubmatch(t)
	if m == nil {
		return k, fmt.Errorf("pep440 %q: %w", s, ErrInvalid)
	}
	g := func(name string) string { return m[pep440Pattern.SubexpIndex(name)] }

	k.epoch = trimZeros(orZero(g("epoch")))

	rel := strings.Split(g("release"), ".")
	for i := range rel {
		rel[i] = trimZeros(rel[i])
	}
	for len(rel) > 0 && rel[len(rel)-1] == "0" {
		rel = rel[:len(rel)-1]
	}
	k.release = rel

	preL, hasPre := g("pre_l"), g("pre") != ""
	postPresent := g("post") != ""
	devPresent := g("dev") != ""

	switch {
	case devPresent && !hasPre && !postPresent:
		// A dev-only release sorts before every pre-release of the same
		// version, not between rc and final. This rank is the whole reason
		// the field is signed.
		k.preRank = -1
	case hasPre:
		switch preL {
		case "a", "alpha":
			k.preRank = 0
		case "b", "beta":
			k.preRank = 1
		default: // c, pre, preview, rc
			k.preRank = 2
		}
	default:
		k.preRank = 3
	}
	k.preN = trimZeros(orZero(g("pre_n")))

	if postPresent {
		k.postRank = 1
		n := g("post_n1")
		if n == "" {
			n = g("post_n2")
		}
		k.postN = trimZeros(orZero(n))
	} else {
		k.postN = "0"
	}

	if devPresent {
		k.devRank = 0
		k.devN = trimZeros(orZero(g("dev_n")))
	} else {
		k.devRank = 1
		k.devN = "0"
	}

	if loc := g("local"); loc != "" {
		k.hasLocal = true
		loc = strings.NewReplacer("-", ".", "_", ".").Replace(loc)
		segs := strings.Split(loc, ".")
		for i, seg := range segs {
			if isNumericID(seg) {
				segs[i] = trimZeros(seg)
			}
		}
		k.local = segs
	}
	return k, nil
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

func trimZeros(s string) string {
	t := strings.TrimLeft(s, "0")
	if t == "" {
		return "0"
	}
	return t
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/version/ -v`
Expected: PASS, including the Task 2 semver tests.

If a row fails, re-derive it from the cited PEP 440 section before changing either the row or the code. The rows most likely to expose a real bug are the dev-only `preRank = -1` cases and the dev-of-post cases (`1.0.post1.dev1 > 1.0`).

- [ ] **Step 5: Commit**

```bash
git add internal/version/pep440.go internal/version/pep440_test.go internal/version/version.go
git commit -m "feat: add PEP 440 comparer for the PyPI ecosystem"
```

---

## Task 4: Range evaluation

**Files:**
- Create: `internal/version/rangeeval.go`
- Test: `internal/version/rangeeval_test.go`

**Interfaces:**
- Consumes: `version.Comparer`, `version.ErrInvalid`; `advisory.Range`, `advisory.Event`, `advisory.RangeType`, `advisory.Affected`.
- Produces: `version.InRange(c Comparer, v string, r advisory.Range) (bool, Evidence, error)` and `version.AffectsVersion(c Comparer, v string, a advisory.Affected) (bool, Evidence, error)`; `version.Evidence{RangeType, Introduced, Fixed, LastAffected, Reason}`.

This task carries the two boundary rules that are easy to get wrong, and one sentinel that causes silent false negatives:

- **`introduced: "0"` is a sentinel, not a version.** OSV defines it as "sorts before any other version". It is *not* `0.0.0`, and it is *not* PEP 440 `0`. Coercing it means `0.0.0-experimental-abc` (real npm) and `v0.0.0-20191109…` (Go pseudo-versions, ubiquitous) sort *below* the lower bound and silently fall outside the range. Resolve it to negative infinity before calling `Compare`.
- **`fixed` is exclusive, `last_affected` is inclusive.** Both appear in live OSV data. Treating them alike shifts every boundary by one version.
- **`GIT` ranges carry commit SHAs.** They must be skipped, never parsed as versions.

- [ ] **Step 1: Write the failing test**

```go
package version

import (
	"errors"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

func rng(t advisory.RangeType, events ...advisory.Event) advisory.Range {
	return advisory.Range{Type: t, Events: events}
}

func intro(v string) advisory.Event   { return advisory.Event{Introduced: v} }
func fixed(v string) advisory.Event   { return advisory.Event{Fixed: v} }
func lastAff(v string) advisory.Event { return advisory.Event{LastAffected: v} }

func TestInRange_Semver(t *testing.T) {
	cases := []struct {
		name string
		v    string
		r    advisory.Range
		want bool
	}{
		// The "0" sentinel: the regression tests that matter most here.
		{"prerelease of 0.0.0 under sentinel", "0.0.0-experimental-abc",
			rng(advisory.RangeSemver, intro("0"), fixed("1.0.0")), true},
		{"go pseudo-version under sentinel", "v0.0.0-20191109021931-daa7c04131f5",
			rng(advisory.RangeSemver, intro("0"), fixed("1.0.0")), true},
		{"zero under sentinel", "0.0.0",
			rng(advisory.RangeSemver, intro("0"), fixed("1.0.0")), true},

		// Half-open: introduced is affected, fixed is not.
		{"at introduced", "1.0.0", rng(advisory.RangeSemver, intro("1.0.0"), fixed("1.0.1")), true},
		{"at fixed", "1.0.0", rng(advisory.RangeSemver, intro("0"), fixed("1.0.0")), false},
		{"below introduced", "1.0.0-rc1", rng(advisory.RangeSemver, intro("1.0.0"), fixed("1.0.1")), false},
		{"prerelease of fixed is affected", "1.0.0-rc1",
			rng(advisory.RangeSemver, intro("0"), fixed("1.0.0")), true},
		{"below range", "0.9.9", rng(advisory.RangeSemver, intro("1.0.0"), fixed("2.0.0")), false},
		{"above range", "2.0.0", rng(advisory.RangeSemver, intro("1.0.0"), fixed("2.0.0")), false},

		// last_affected is inclusive, unlike fixed.
		{"at last_affected", "1.0.0", rng(advisory.RangeSemver, intro("0"), lastAff("1.0.0")), true},
		{"above last_affected", "1.0.1", rng(advisory.RangeSemver, intro("0"), lastAff("1.0.0")), false},

		// Open-ended upper bound.
		{"open ended", "99.0.0", rng(advisory.RangeSemver, intro("1.0.0")), true},
		{"open ended below", "0.1.0", rng(advisory.RangeSemver, intro("1.0.0")), false},

		// Multiple introduced/fixed pairs in one range.
		{"second window", "2.5.0", rng(advisory.RangeSemver,
			intro("1.0.0"), fixed("1.5.0"), intro("2.0.0"), fixed("3.0.0")), true},
		{"between windows", "1.7.0", rng(advisory.RangeSemver,
			intro("1.0.0"), fixed("1.5.0"), intro("2.0.0"), fixed("3.0.0")), false},

		// v-prefixed artifact against bare bounds.
		{"v prefix", "v1.2.3", rng(advisory.RangeSemver, intro("1.2.0"), fixed("1.2.4")), true},
		{"incompatible build metadata", "v2.0.0+incompatible",
			rng(advisory.RangeSemver, intro("2.0.0"), fixed("2.0.1")), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := InRange(SemVer{}, tc.v, tc.r)
			if err != nil {
				t.Fatalf("InRange(%q) error: %v", tc.v, err)
			}
			if got != tc.want {
				t.Errorf("InRange(%q) = %v, want %v", tc.v, got, tc.want)
			}
		})
	}
}

func TestInRange_PEP440Sentinel(t *testing.T) {
	// The same sentinel trap exists for PyPI: 0.dev0 and 0a1 both sort BELOW
	// the literal version "0", so coercing the sentinel misses them.
	for _, v := range []string{"0.dev0", "0a1", "0.0.0rc1", "0"} {
		got, _, err := InRange(PEP440{}, v, rng(advisory.RangeEcosystem, intro("0"), fixed("1.0")))
		if err != nil {
			t.Fatalf("InRange(%q) error: %v", v, err)
		}
		if !got {
			t.Errorf("InRange(%q) = false, want true (sentinel must be -inf)", v)
		}
	}
}

func TestInRange_GitSkipped(t *testing.T) {
	// GIT ranges carry commit SHAs. Feeding them to a Comparer would error;
	// the range must be skipped instead, with no error surfaced.
	r := rng(advisory.RangeGit, intro("9305c0e12d43c4df999c3301a1f0c742264a657e"))
	got, _, err := InRange(SemVer{}, "1.0.0", r)
	if err != nil {
		t.Fatalf("InRange over GIT range error: %v", err)
	}
	if got {
		t.Error("InRange over GIT range = true, want false")
	}
}

func TestInRange_InvalidVersionErrors(t *testing.T) {
	// An unparseable installed version must surface, not evaluate to false.
	_, _, err := InRange(SemVer{}, "not-a-version",
		rng(advisory.RangeSemver, intro("0"), fixed("1.0.0")))
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("InRange err = %v, want ErrInvalid", err)
	}
}

func TestInRange_UnsortedEvents(t *testing.T) {
	// OSV only recommends sorted events, so a later window listed first is
	// well-formed. Walking in file order returns false with no error — a
	// silent miss on valid input.
	r := rng(advisory.RangeSemver,
		intro("2.0.0"), fixed("3.0.0"),
		intro("1.0.0"), fixed("1.5.0"))
	for _, tc := range []struct {
		v    string
		want bool
	}{
		{"2.5.0", true},  // inside the window that was listed first
		{"1.2.0", true},  // inside the window that was listed second
		{"1.7.0", false}, // between the two windows
		{"3.0.0", false}, // at the upper fix, exclusive
	} {
		got, _, err := InRange(SemVer{}, tc.v, r)
		if err != nil {
			t.Fatalf("InRange(%q) error: %v", tc.v, err)
		}
		if got != tc.want {
			t.Errorf("InRange(%q) over unsorted events = %v, want %v", tc.v, got, tc.want)
		}
	}
}

func TestInRange_MalformedBoundErrors(t *testing.T) {
	// A bound that cannot be ordered must surface. Sorting on an unorderable
	// bound would otherwise pick an arbitrary order and return a confident
	// wrong verdict.
	_, _, err := InRange(SemVer{}, "1.2.3",
		rng(advisory.RangeSemver, intro("1.0.0"), fixed("not-a-version")))
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("InRange with a malformed bound err = %v, want ErrInvalid", err)
	}
}

func TestInRange_EvidenceNamesTheContainingWindow(t *testing.T) {
	// With several maintenance branches, evidence must cite the fix for the
	// window the version is actually in. Naming a later window's fix sends the
	// user to the wrong upgrade.
	r := rng(advisory.RangeSemver,
		intro("1.0.0"), fixed("1.5.0"),
		intro("2.0.0"), fixed("3.0.0"))
	got, ev, err := InRange(SemVer{}, "1.2.0", r)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("InRange = false, want true")
	}
	if ev.Introduced != "1.0.0" || ev.Fixed != "1.5.0" {
		t.Errorf("Evidence = introduced %q fixed %q, want 1.0.0 / 1.5.0",
			ev.Introduced, ev.Fixed)
	}
}

func TestAffectsVersion_EnumeratedPropagatesCompareError(t *testing.T) {
	// The installed version is the left operand on every iteration, so an
	// unparseable one fails every entry. Skipping would turn a total failure
	// into a silent clean verdict.
	a := advisory.Affected{
		Ecosystem: "Go",
		Name:      "x",
		Versions:  []string{"1.0.0", "2.0.0"},
	}
	_, _, err := AffectsVersion(SemVer{}, "not-a-version", a)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("AffectsVersion err = %v, want ErrInvalid", err)
	}
}

func TestInRange_Evidence(t *testing.T) {
	_, ev, err := InRange(SemVer{}, "1.2.3",
		rng(advisory.RangeSemver, intro("1.0.0"), fixed("2.0.0")))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Introduced != "1.0.0" || ev.Fixed != "2.0.0" {
		t.Errorf("Evidence = %+v, want introduced=1.0.0 fixed=2.0.0", ev)
	}
	if ev.RangeType != advisory.RangeSemver {
		t.Errorf("Evidence.RangeType = %q, want SEMVER", ev.RangeType)
	}
	if ev.Reason == "" {
		t.Error("Evidence.Reason is empty; a finding must be able to explain itself")
	}
}

func TestAffectsVersion_EnumeratedOnly(t *testing.T) {
	// When an Affected carries no Ranges, the enumerated Versions list is the
	// only matching data available.
	a := advisory.Affected{
		Ecosystem: "PyPI",
		Name:      "django",
		Versions:  []string{"1.0", "1.0.1", "2.0"},
	}
	for _, tc := range []struct {
		v    string
		want bool
	}{
		{"1.0", true},
		{"1.0.0", true}, // equal under PEP 440 even though the strings differ
		{"1.5", false},
	} {
		got, _, err := AffectsVersion(PEP440{}, tc.v, a)
		if err != nil {
			t.Fatalf("AffectsVersion(%q) error: %v", tc.v, err)
		}
		if got != tc.want {
			t.Errorf("AffectsVersion(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/version/ -run 'TestInRange|TestAffects' -v`
Expected: FAIL — `InRange`, `AffectsVersion`, and `Evidence` undefined.

- [ ] **Step 3: Write the implementation**

```go
package version

import (
	"fmt"
	"sort"

	"github.com/kun9497/assay/internal/advisory"
)

// introducedSentinel is OSV's "sorts before any other version" marker. It is
// NOT a version: coercing it to 0.0.0 (semver) or 0 (PEP 440) puts it ABOVE
// real prerelease builds such as 0.0.0-experimental-abc and Go pseudo-versions,
// which then fall outside the range and are silently missed.
const introducedSentinel = "0"

// Evidence records why a comparison decided what it decided (D10). It exists on
// the type rather than in a log line because explainability is goal #1, and
// anything left to logging effectively does not exist.
type Evidence struct {
	RangeType    advisory.RangeType
	Introduced   string
	Fixed        string
	LastAffected string
	Reason       string
}

// AffectsVersion reports whether v falls within any range of a, falling back to
// the enumerated Versions list when a carries no usable ranges.
func AffectsVersion(c Comparer, v string, a advisory.Affected) (bool, Evidence, error) {
	for _, r := range a.Ranges {
		hit, ev, err := InRange(c, v, r)
		if err != nil {
			return false, Evidence{}, err
		}
		if hit {
			return true, ev, nil
		}
	}
	// Versions is redundant with Ranges when both are present, but it is the
	// only data when Ranges is absent, so it cannot be dropped.
	for _, known := range a.Versions {
		cmp, err := c.Compare(v, known)
		if err != nil {
			// Surface it. The left operand is the installed version and is
			// identical on every iteration, so an unparseable one fails every
			// entry — skipping would turn a 100% failure rate into a silent
			// clean verdict, which is the exact false negative this package
			// exists to prevent.
			return false, Evidence{}, fmt.Errorf("compare %q to listed version %q: %w", v, known, err)
		}
		if cmp == 0 {
			return true, Evidence{
				Reason: fmt.Sprintf("version %s is listed as affected", v),
			}, nil
		}
	}
	return false, Evidence{}, nil
}

// InRange walks an OSV range's events in ascending version order, tracking
// whether v is currently inside an open window. Windows are half-open
// [introduced, fixed), with the exception of last_affected, which is inclusive.
func InRange(c Comparer, v string, r advisory.Range) (bool, Evidence, error) {
	// GIT ranges carry commit SHAs, not versions. Skipping is correct; parsing
	// would error on data that was never meant for a Comparer.
	if r.Type == advisory.RangeGit {
		return false, Evidence{}, nil
	}

	// OSV only *recommends* that events arrive sorted, and its reference
	// algorithm sorts before walking. An advisory that lists a later window
	// first is well-formed, and walking it in file order returns "not
	// vulnerable" with no error — a silent miss on valid input.
	events, err := sortEvents(c, r.Events)
	if err != nil {
		return false, Evidence{}, err
	}

	var (
		inside bool
		ev     Evidence
	)
	ev.RangeType = r.Type

	for _, e := range events {
		switch {
		case e.Introduced != "":
			ge, err := atLeast(c, v, e.Introduced)
			if err != nil {
				return false, Evidence{}, err
			}
			if ge {
				inside = true
				ev.Introduced = e.Introduced
				ev.Fixed, ev.LastAffected = "", ""
			}

		case e.Fixed != "":
			cmp, err := c.Compare(v, e.Fixed)
			if err != nil {
				return false, Evidence{}, fmt.Errorf("compare %q to fixed %q: %w", v, e.Fixed, err)
			}
			if inside && cmp >= 0 {
				inside = false // exclusive upper bound
			} else if inside && ev.Fixed == "" && ev.LastAffected == "" {
				// Only the bound closing the window v actually sits in. A
				// later window's bound would name the wrong fix version, and
				// wrong remediation advice is worse than none.
				ev.Fixed = e.Fixed
			}

		case e.LastAffected != "":
			cmp, err := c.Compare(v, e.LastAffected)
			if err != nil {
				return false, Evidence{}, fmt.Errorf("compare %q to last_affected %q: %w", v, e.LastAffected, err)
			}
			if inside && cmp > 0 {
				inside = false // inclusive upper bound: equal is still affected
			} else if inside && ev.Fixed == "" && ev.LastAffected == "" {
				ev.LastAffected = e.LastAffected
			}
		}
	}

	if inside {
		ev.Reason = describe(v, ev)
	}
	return inside, ev, nil
}

// eventVersion returns whichever bound an event carries, or "" for an event
// this slice does not act on (a bare `limit`, or a malformed empty event).
func eventVersion(e advisory.Event) string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	case e.LastAffected != "":
		return e.LastAffected
	}
	return ""
}

// sortEvents orders events by the version each carries, with the introduced
// sentinel first.
//
// Every bound is validated before sorting so the comparator cannot fail. A
// comparator that swallowed errors would silently produce an arbitrary order,
// and an arbitrary order here is a wrong verdict with no error attached —
// strictly worse than refusing to evaluate the range.
func sortEvents(c Comparer, in []advisory.Event) ([]advisory.Event, error) {
	out := append([]advisory.Event(nil), in...)
	for _, e := range out {
		ver := eventVersion(e)
		if ver == "" || ver == introducedSentinel {
			continue
		}
		if _, err := c.Compare(ver, ver); err != nil {
			return nil, fmt.Errorf("range event bound %q: %w", ver, err)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		vi, vj := eventVersion(out[i]), eventVersion(out[j])
		// The sentinel is negative infinity, so it sorts before everything.
		if vi == introducedSentinel {
			return vj != introducedSentinel
		}
		if vj == introducedSentinel {
			return false
		}
		cmp, _ := c.Compare(vi, vj) // cannot fail: validated above
		return cmp < 0
	})
	return out, nil
}

// atLeast reports whether v >= bound, resolving the OSV sentinel first.
func atLeast(c Comparer, v, bound string) (bool, error) {
	if bound == introducedSentinel {
		return true, nil // negative infinity: everything is at or above it
	}
	cmp, err := c.Compare(v, bound)
	if err != nil {
		return false, fmt.Errorf("compare %q to introduced %q: %w", v, bound, err)
	}
	return cmp >= 0, nil
}

func describe(v string, ev Evidence) string {
	lower := ev.Introduced
	if lower == introducedSentinel {
		lower = "any earlier version"
	}
	switch {
	case ev.Fixed != "":
		return fmt.Sprintf("%s is at or above %s and below the fix %s", v, lower, ev.Fixed)
	case ev.LastAffected != "":
		return fmt.Sprintf("%s is at or above %s and at or below %s", v, lower, ev.LastAffected)
	default:
		return fmt.Sprintf("%s is at or above %s, with no fixed version recorded", v, lower)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/version/ -v`
Expected: PASS, all range and comparer tests.

- [ ] **Step 5: Commit**

```bash
git add internal/version/rangeeval.go internal/version/rangeeval_test.go
git commit -m "feat: evaluate OSV ranges with sentinel and last_affected handling"
```

---

## Task 5: bbolt store

**Files:**
- Create: `internal/store/store.go`
- Create: `internal/store/bolt.go`
- Test: `internal/store/bolt_test.go`
- Modify: `go.mod`, `go.sum` — add `go.etcd.io/bbolt v1.5.0`

**Interfaces:**
- Consumes: `advisory.Advisory`.
- Produces: `store.Store` interface (`Lookup`, `LookupBySource`, `Meta`, `Close`); `store.Writer` interface (`Put`, `SetMeta`, `Commit`); `store.Meta{Schema, BuiltAt, Providers}`; `store.Provenance{Source, DataAsOf, Records}`; `store.Open(path string) (*Bolt, error)`; `store.Create(path string) (*Bolt, error)`; `store.DefaultPath() (string, error)`; sentinel errors `store.ErrNotFound`, `store.ErrSchemaMismatch`.

Two design points from the roadmap that the implementation must honor:

- **Lookup buckets hold advisory IDs, not records.** One advisory routinely affects several packages — 1,452 of 8,510 in the Go dump, up to 22 — so keying records by package stores them repeatedly. Measured blowup is 1.44x, and with `by-id` keeping its own copy the naive layout turns 21.9 MB into 53.6 MB.
- **`Provenance.DataAsOf` is upstream data time, not local build time** (D12). A mirror serving a three-month-old snapshot fetched today must not report as fresh.

- [ ] **Step 1: Write the failing test**

```go
package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

func sample(id, ecosystem, name string) advisory.Advisory {
	return advisory.Advisory{
		ID:       id,
		Source:   "osv",
		Kind:     advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: ecosystem, Name: name}},
	}
}

func buildTestDB(t *testing.T, advs ...advisory.Advisory) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, a := range advs {
		if err := w.Put(a); err != nil {
			t.Fatalf("Put(%s): %v", a.ID, err)
		}
	}
	err = w.SetMeta(Meta{
		BuiltAt: time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC),
		Providers: map[string]Provenance{
			"osv": {
				Source:   "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
				DataAsOf: time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC),
				Records:  len(advs),
			},
		},
	})
	if err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return path
}

func TestLookup(t *testing.T) {
	path := buildTestDB(t,
		sample("GHSA-aaa", "Go", "github.com/foo/bar"),
		sample("GHSA-bbb", "Go", "github.com/foo/bar"),
		sample("GHSA-ccc", "npm", "lodash"),
	)
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	got, err := db.Lookup("Go", "github.com/foo/bar")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Lookup returned %d advisories, want 2", len(got))
	}
	ids := map[string]bool{got[0].ID: true, got[1].ID: true}
	if !ids["GHSA-aaa"] || !ids["GHSA-bbb"] {
		t.Errorf("Lookup returned %v, want GHSA-aaa and GHSA-bbb", ids)
	}

	none, err := db.Lookup("Go", "github.com/nobody/nothing")
	if err != nil {
		t.Fatalf("Lookup miss: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("Lookup miss returned %d advisories, want 0", len(none))
	}
}

func TestLookupDoesNotDuplicateRecords(t *testing.T) {
	// One advisory affecting three packages must be stored once and returned
	// under each key. This is the property that keeps the database from
	// growing 1.44x.
	multi := advisory.Advisory{
		ID:     "GHSA-multi",
		Source: "osv",
		Kind:   advisory.KindVulnerability,
		Affected: []advisory.Affected{
			{Ecosystem: "Go", Name: "a"},
			{Ecosystem: "Go", Name: "b"},
			{Ecosystem: "Go", Name: "c"},
		},
	}
	db, err := Open(buildTestDB(t, multi))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, name := range []string{"a", "b", "c"} {
		got, err := db.Lookup("Go", name)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}
		if len(got) != 1 || got[0].ID != "GHSA-multi" {
			t.Errorf("Lookup(%q) = %+v, want one GHSA-multi", name, got)
		}
	}
	if n := db.RecordCount(); n != 1 {
		t.Errorf("RecordCount = %d, want 1 (record stored once, not per package)", n)
	}
}

func TestLookupBySource(t *testing.T) {
	a := advisory.Advisory{
		ID:     "ALPINE-CVE-1",
		Source: "osv",
		Kind:   advisory.KindVulnerability,
		Affected: []advisory.Affected{
			{Ecosystem: "Alpine:v3.19", Name: "apache2"},
		},
	}
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutSourceIndex("Alpine:v3.19", "apache2", a.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	got, err := db.LookupBySource("Alpine:v3.19", "apache2")
	if err != nil {
		t.Fatalf("LookupBySource: %v", err)
	}
	if len(got) != 1 || got[0].ID != "ALPINE-CVE-1" {
		t.Errorf("LookupBySource = %+v, want ALPINE-CVE-1", got)
	}
}

func TestMeta(t *testing.T) {
	db, err := Open(buildTestDB(t, sample("GHSA-aaa", "Go", "x")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m, err := db.Meta()
	if err != nil {
		t.Fatalf("Meta: %v", err)
	}
	if m.Schema != SchemaVersion {
		t.Errorf("Meta.Schema = %d, want %d", m.Schema, SchemaVersion)
	}
	p, ok := m.Providers["osv"]
	if !ok {
		t.Fatal("Meta.Providers missing osv")
	}
	// DataAsOf must survive as upstream data time, distinct from BuiltAt (D12).
	if !p.DataAsOf.Equal(time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("DataAsOf = %v, want 2026-07-29", p.DataAsOf)
	}
	if !m.BuiltAt.After(p.DataAsOf) {
		t.Error("BuiltAt should be distinct from and later than DataAsOf in this fixture")
	}
}

func TestOpenMissing(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "absent.db"))
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Open(absent) err = %v, want ErrNotFound", err)
	}
}

func TestOpenSchemaMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.setSchemaForTest(SchemaVersion + 1); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrSchemaMismatch) {
		t.Errorf("Open(mismatched) err = %v, want ErrSchemaMismatch", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/ -v`
Expected: FAIL — package does not compile.

- [ ] **Step 3: Add the dependency and write the implementation**

```bash
go get go.etcd.io/bbolt@v1.5.0
```

`internal/store/store.go`:

```go
// Package store holds the local advisory database.
//
// The database is orthogonal to a scan (D14): providers write it through
// `assay db update` and a scan only ever reads. That is what makes offline
// operation the default rather than a flag.
package store

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// SchemaVersion is part of the on-disk path (D5). A schema change rebuilds
// into a new directory rather than migrating in place, because migration code
// is a liability for a project with one user.
const SchemaVersion = 1

var (
	ErrNotFound       = errors.New("vulnerability database not found")
	ErrSchemaMismatch = errors.New("vulnerability database schema mismatch")
)

type Store interface {
	Lookup(ecosystem, name string) ([]advisory.Advisory, error)
	// LookupBySource resolves advisories keyed on a source package (D8).
	// Unused in slice 1 — distro packages arrive in slice 2 — but present so
	// the interface does not change under its first real consumer.
	LookupBySource(ecosystem, sourceName string) ([]advisory.Advisory, error)
	Meta() (Meta, error)
	Close() error
}

type Meta struct {
	Schema    int                   `json:"schema"`
	BuiltAt   time.Time             `json:"built_at"` // when this database was assembled locally
	Providers map[string]Provenance `json:"providers"`
}

type Provenance struct {
	Source string `json:"source"` // the URL actually fetched
	// DataAsOf is when the UPSTREAM data was current, which is not the same as
	// BuiltAt (D12). A mirror serving a stale snapshot fetched today has a
	// recent BuiltAt and an old DataAsOf; judging freshness by the former
	// reports quarter-old data as fresh.
	DataAsOf time.Time `json:"data_as_of"`
	Records  int       `json:"records"`
}

// DefaultPath returns <user cache>/assay/db/v<schema>/vulnerability.db,
// honouring ASSAY_DB_DIR for CI caching and air-gapped environments.
func DefaultPath() (string, error) {
	if dir := os.Getenv("ASSAY_DB_DIR"); dir != "" {
		return filepath.Join(dir, "vulnerability.db"), nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "assay", "db", "v1", "vulnerability.db"), nil
}
```

`internal/store/bolt.go`:

```go
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	bolt "go.etcd.io/bbolt"

	"github.com/kun9497/assay/internal/advisory"
)

var (
	bucketAdvisories = []byte("advisories") // "<ecosystem>\x00<name>"   -> []advisory ID
	bucketBySource   = []byte("by-source")  // "<ecosystem>\x00<source>" -> []advisory ID
	bucketByID       = []byte("by-id")      // "<advisory ID>"           -> the record, once
	bucketMeta       = []byte("meta")
)

var allBuckets = [][]byte{bucketAdvisories, bucketBySource, bucketByID, bucketMeta}

const keySep = "\x00"

type Bolt struct {
	db *bolt.DB
}

// Open opens an existing database read-only. A missing or schema-mismatched
// database is an error, never an empty result: the scan path must exit 2 with
// instructions rather than reporting a clean scan it did not perform (D14).
func Open(path string) (*Bolt, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("%w at %s", ErrNotFound, path)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	b := &Bolt{db: db}
	m, err := b.Meta()
	if err != nil {
		db.Close()
		return nil, err
	}
	if m.Schema != SchemaVersion {
		db.Close()
		return nil, fmt.Errorf("%w: found v%d, want v%d", ErrSchemaMismatch, m.Schema, SchemaVersion)
	}
	return b, nil
}

// Create makes a fresh database for writing. Callers build into a temporary
// path and rename over the live database so a concurrent scan never observes a
// partial write.
func Create(path string) (*Bolt, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return tx.Bucket(bucketMeta).Put([]byte("schema"),
			[]byte(strconv.Itoa(SchemaVersion)))
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Bolt{db: db}, nil
}

func (b *Bolt) Close() error { return b.db.Close() }

// Put stores one advisory once in by-id and appends its ID to the lookup key of
// every package it affects. Storing IDs rather than records is what keeps the
// database from growing by the 1.44x measured duplication factor.
func (b *Bolt) Put(a advisory.Advisory) error {
	blob, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", a.ID, err)
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketByID).Put([]byte(a.ID), blob); err != nil {
			return err
		}
		idx := tx.Bucket(bucketAdvisories)
		for _, aff := range a.Affected {
			if aff.Ecosystem == "" || aff.Name == "" {
				continue
			}
			if err := appendID(idx, aff.Ecosystem+keySep+aff.Name, a.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// PutSourceIndex records that an advisory is keyed on a source package (D8).
func (b *Bolt) PutSourceIndex(ecosystem, sourceName, id string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		return appendID(tx.Bucket(bucketBySource), ecosystem+keySep+sourceName, id)
	})
}

func appendID(bk *bolt.Bucket, key, id string) error {
	var ids []string
	if raw := bk.Get([]byte(key)); raw != nil {
		if err := json.Unmarshal(raw, &ids); err != nil {
			return fmt.Errorf("decode index %q: %w", key, err)
		}
		for _, existing := range ids {
			if existing == id {
				return nil
			}
		}
	}
	ids = append(ids, id)
	blob, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return bk.Put([]byte(key), blob)
}

func (b *Bolt) SetMeta(m Meta) error {
	m.Schema = SchemaVersion
	blob, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put([]byte("meta"), blob)
	})
}

// Commit flushes and closes the write handle.
func (b *Bolt) Commit() error { return b.db.Close() }

func (b *Bolt) setSchemaForTest(v int) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		blob, err := json.Marshal(Meta{Schema: v})
		if err != nil {
			return err
		}
		return tx.Bucket(bucketMeta).Put([]byte("meta"), blob)
	})
}

func (b *Bolt) Lookup(ecosystem, name string) ([]advisory.Advisory, error) {
	return b.resolve(bucketAdvisories, ecosystem+keySep+name)
}

func (b *Bolt) LookupBySource(ecosystem, sourceName string) ([]advisory.Advisory, error) {
	return b.resolve(bucketBySource, ecosystem+keySep+sourceName)
}

func (b *Bolt) resolve(index []byte, key string) ([]advisory.Advisory, error) {
	var out []advisory.Advisory
	err := b.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(index).Get([]byte(key))
		if raw == nil {
			return nil
		}
		var ids []string
		if err := json.Unmarshal(raw, &ids); err != nil {
			return fmt.Errorf("decode index %q: %w", key, err)
		}
		byID := tx.Bucket(bucketByID)
		for _, id := range ids {
			blob := byID.Get([]byte(id))
			if blob == nil {
				// A dangling index entry means the database is inconsistent.
				// Fail loudly rather than returning a short list that reads as
				// "fewer vulnerabilities".
				return fmt.Errorf("index %q references missing advisory %q", key, id)
			}
			var a advisory.Advisory
			if err := json.Unmarshal(blob, &a); err != nil {
				return fmt.Errorf("decode advisory %q: %w", id, err)
			}
			out = append(out, a)
		}
		return nil
	})
	return out, err
}

func (b *Bolt) Meta() (Meta, error) {
	var m Meta
	err := b.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketMeta)
		if bk == nil {
			return ErrNotFound
		}
		if raw := bk.Get([]byte("meta")); raw != nil {
			return json.Unmarshal(raw, &m)
		}
		if raw := bk.Get([]byte("schema")); raw != nil {
			v, err := strconv.Atoi(string(raw))
			if err != nil {
				return err
			}
			m.Schema = v
		}
		return nil
	})
	return m, err
}

// RecordCount reports how many advisories are stored, independent of how many
// index entries point at them.
func (b *Bolt) RecordCount() int {
	var n int
	_ = b.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(bucketByID).Stats().KeyN
		return nil
	})
	return n
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/ -v`
Expected: PASS, all six test functions.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/store
git commit -m "feat: add bbolt advisory store keyed by ID to avoid duplication"
```

---

## Task 6: OSV record parser

**Files:**
- Create: `internal/provider/provider.go`
- Create: `internal/provider/osv/record.go`
- Test: `internal/provider/osv/record_test.go`

**Interfaces:**
- Consumes: `advisory.Advisory` and friends; `store.Provenance`.
- Produces: `provider.Provider` interface with `Name() string` and `Fetch(ctx, func(advisory.Advisory) error) (store.Provenance, error)`; `osv.Convert(raw []byte, wantEcosystem string) (advisory.Advisory, bool, error)` returning `ok=false` for records that are filtered rather than broken.

Four filters, each protecting against a specific silent failure:

- **Withdrawn records are dropped** (D16). 107 of 8,617 Go records carry a `withdrawn` timestamp; ingesting them produces findings for retracted advisories, which are plain false positives. Filtering here rather than at query time means no lookup path can forget the check.
- **`MAL-*` records are dropped** (D15), keeping `Kind` on the record so enabling them later is a filter change rather than a schema change.
- **Affected entries for other ecosystems are dropped.** A single advisory can carry entries for several ecosystems — a django advisory in live OSV data contained an npm entry whose ranges were `SEMVER`, inside a record otherwise full of PyPI `ECOSYSTEM` ranges. Without this filter, npm version strings reach the PEP 440 comparer.
- **`GIT` ranges are dropped at conversion.** They carry commit SHAs; `PYSEC-*` records are full of them.

Range endpoints are stored verbatim, not normalized. OSV publishes non-canonical forms — `1.7c3`, `1.8c1`, `4.0.0.beta1` all appear in live PyPI data — and normalization is the comparer's job (D13: store losslessly, derive at query time). A string comparison against `1.8rc1` would fail silently.

- [ ] **Step 1: Write the failing test**

```go
package osv

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

const goRecord = `{
  "schema_version": "1.7.3",
  "id": "GHSA-227x-7mh8-3cf6",
  "modified": "2025-10-23T20:12:12Z",
  "aliases": ["CVE-2025-59823", "GO-2025-3981"],
  "summary": "Code injection in Gardener provider extensions",
  "affected": [
    {
      "package": {"name": "github.com/gardener/a", "ecosystem": "Go"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.64.0"}]}]
    },
    {
      "package": {"name": "github.com/gardener/b", "ecosystem": "Go"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.46.0"}]}]
    }
  ],
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]
}`

func TestConvert_Go(t *testing.T) {
	got, ok, err := Convert([]byte(goRecord), "Go")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if !ok {
		t.Fatal("Convert returned ok=false, want a converted advisory")
	}
	if got.ID != "GHSA-227x-7mh8-3cf6" {
		t.Errorf("ID = %q", got.ID)
	}
	if got.Source != "osv" {
		t.Errorf("Source = %q, want osv", got.Source)
	}
	if got.Kind != advisory.KindVulnerability {
		t.Errorf("Kind = %q, want vulnerability", got.Kind)
	}
	if len(got.Affected) != 2 {
		t.Fatalf("Affected = %d entries, want 2", len(got.Affected))
	}
	if got.Affected[0].Ranges[0].Events[0].Introduced != "0" {
		t.Error("the introduced sentinel must survive conversion verbatim")
	}
	if len(got.Severity) != 1 || got.Severity[0].Type != "CVSS_V3" {
		t.Errorf("Severity = %+v, want one CVSS_V3 vector", got.Severity)
	}
	// Both alias fields feed the KISA join (D3); this record uses aliases.
	if len(got.Aliases) != 2 {
		t.Errorf("Aliases = %v, want 2", got.Aliases)
	}
}

func TestConvert_UpstreamFieldIsCarried(t *testing.T) {
	// OSV 1.7 puts the CVE link in `upstream`. A record can have upstream and
	// no aliases at all; reading only one field makes the KISA join fail
	// silently (D3).
	const rec = `{
	  "id": "ALPINE-CVE-2006-20001",
	  "upstream": ["CVE-2006-20001"],
	  "affected": [{"package": {"name": "apache2", "ecosystem": "Alpine:v3.19"},
	                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.4.55-r0"}]}]}]
	}`
	got, ok, err := Convert([]byte(rec), "Alpine:v3.19")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Upstream) != 1 || got.Upstream[0] != "CVE-2006-20001" {
		t.Errorf("Upstream = %v, want [CVE-2006-20001]", got.Upstream)
	}
	if len(got.Aliases) != 0 {
		t.Errorf("Aliases = %v, want empty", got.Aliases)
	}
}

func TestConvert_DropsWithdrawn(t *testing.T) {
	const rec = `{
	  "id": "GHSA-withdrawn",
	  "withdrawn": "2024-01-01T00:00:00Z",
	  "affected": [{"package": {"name": "x", "ecosystem": "Go"},
	                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]
	}`
	_, ok, err := Convert([]byte(rec), "Go")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if ok {
		t.Error("withdrawn record was converted; it must be dropped (D16)")
	}
}

func TestConvert_DropsMalicious(t *testing.T) {
	const rec = `{
	  "id": "MAL-2021-1",
	  "summary": "Malicious code in cxp-jquery (npm)",
	  "affected": [{"package": {"name": "cxp-jquery", "ecosystem": "npm"},
	                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]
	}`
	_, ok, err := Convert([]byte(rec), "npm")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if ok {
		t.Error("MAL record was converted; it must be dropped in slice 1 (D15)")
	}
}

func TestConvert_FiltersForeignEcosystems(t *testing.T) {
	// Live OSV data mixes ecosystems inside one advisory. Without this filter
	// the npm SEMVER value reaches the PEP 440 comparer.
	const rec = `{
	  "id": "GHSA-mixed",
	  "affected": [
	    {"package": {"name": "django", "ecosystem": "PyPI"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.2.1"}]}]},
	    {"package": {"name": "some-js-lib", "ecosystem": "npm"},
	     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "v1.16.3"}]}]}
	  ]
	}`
	got, ok, err := Convert([]byte(rec), "PyPI")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Affected) != 1 {
		t.Fatalf("Affected = %d entries, want 1 (npm entry must be dropped)", len(got.Affected))
	}
	if got.Affected[0].Ecosystem != "PyPI" || got.Affected[0].Name != "django" {
		t.Errorf("Affected[0] = %+v, want the PyPI django entry", got.Affected[0])
	}
}

func TestConvert_DropsGitRanges(t *testing.T) {
	const rec = `{
	  "id": "PYSEC-git",
	  "affected": [{"package": {"name": "django", "ecosystem": "PyPI"},
	    "ranges": [
	      {"type": "GIT", "repo": "https://github.com/django/django",
	       "events": [{"introduced": "9305c0e12d43c4df999c3301a1f0c742264a657e"}]},
	      {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.2.1"}]}
	    ]}]
	}`
	got, ok, err := Convert([]byte(rec), "PyPI")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	rs := got.Affected[0].Ranges
	if len(rs) != 1 || rs[0].Type != advisory.RangeEcosystem {
		t.Errorf("Ranges = %+v, want only the ECOSYSTEM range", rs)
	}
}

func TestConvert_KeepsNonCanonicalEndpointsVerbatim(t *testing.T) {
	// OSV publishes non-normalized PyPI endpoints. Normalizing here would be
	// lossy (D13); the comparer handles it.
	const rec = `{
	  "id": "PYSEC-noncanon",
	  "affected": [{"package": {"name": "django", "ecosystem": "PyPI"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.8c1"}]}],
	    "versions": ["1.5c1", "4.0.0.beta1"]}]
	}`
	got, _, err := Convert([]byte(rec), "PyPI")
	if err != nil {
		t.Fatal(err)
	}
	if f := got.Affected[0].Ranges[0].Events[1].Fixed; f != "1.8c1" {
		t.Errorf("fixed = %q, want the verbatim 1.8c1", f)
	}
	if got.Affected[0].Versions[1] != "4.0.0.beta1" {
		t.Errorf("versions = %v, want verbatim", got.Affected[0].Versions)
	}
}

func TestConvert_DropsRecordWithNoMatchingAffected(t *testing.T) {
	const rec = `{
	  "id": "GHSA-elsewhere",
	  "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
	                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]
	}`
	_, ok, err := Convert([]byte(rec), "Go")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if ok {
		t.Error("record with no Go entries was converted; it must be dropped")
	}
}

func TestConvert_Malformed(t *testing.T) {
	if _, _, err := Convert([]byte("{not json"), "Go"); err == nil {
		t.Error("Convert(malformed) = nil error, want error")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/provider/osv/ -v`
Expected: FAIL — package does not compile, `Convert` undefined.

- [ ] **Step 3: Write the implementation**

`internal/provider/provider.go`:

```go
// Package provider defines how upstream advisory data enters the store.
//
// The abstraction exists from day one (D2) because KISA/KNVD data will not
// arrive in OSV format, so some collection and normalization is unavoidable —
// but committing to hand-rolling every upstream feed is not.
package provider

import (
	"context"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

type Provider interface {
	Name() string
	// Fetch streams advisories to emit rather than returning a slice: the
	// unfiltered OSV download is ~244 MB for slice 1's ecosystems, most of
	// which is discarded, and holding it all in memory buys nothing.
	Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error)
}
```

`internal/provider/osv/record.go`:

```go
// Package osv converts OSV records into the internal advisory shape.
//
// OSV is the primary provider and passes through nearly unchanged (D1) — the
// internal type IS the OSV shape. What this package does is filter.
package osv

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// SourceName identifies records this provider supplied (D15's groundwork for
// splitting data by provider later).
const SourceName = "osv"

type rawRecord struct {
	ID        string        `json:"id"`
	Summary   string        `json:"summary"`
	Modified  time.Time     `json:"modified"`
	Withdrawn *time.Time    `json:"withdrawn"`
	Aliases   []string      `json:"aliases"`
	Upstream  []string      `json:"upstream"`
	Affected  []rawAffected `json:"affected"`
	Severity  []rawSeverity `json:"severity"`
}

type rawAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges   []rawRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type rawRange struct {
	Type   string     `json:"type"`
	Events []rawEvent `json:"events"`
}

type rawEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

type rawSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Convert parses one OSV record and keeps only the parts relevant to
// wantEcosystem. ok is false when the record is deliberately filtered out;
// err is non-nil only when the record is malformed. Distinguishing the two
// keeps "we chose to skip this" from looking like "the database is broken".
func Convert(data []byte, wantEcosystem string) (advisory.Advisory, bool, error) {
	var r rawRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return advisory.Advisory{}, false, fmt.Errorf("decode osv record: %w", err)
	}
	if r.ID == "" {
		return advisory.Advisory{}, false, fmt.Errorf("osv record has no id")
	}

	// Withdrawn advisories were retracted upstream; reporting them is a plain
	// false positive. Dropped here rather than at query time so no lookup path
	// can forget the check (D16).
	if r.Withdrawn != nil {
		return advisory.Advisory{}, false, nil
	}

	kind := advisory.KindVulnerability
	if strings.HasPrefix(r.ID, "MAL-") {
		kind = advisory.KindMalicious
	}
	// Malicious-package reports are a different finding class with no severity
	// and no fixed version (D15). Kind is computed above and would be stored
	// faithfully; the filter is what changes when they are enabled.
	if kind != advisory.KindVulnerability {
		return advisory.Advisory{}, false, nil
	}

	out := advisory.Advisory{
		ID:       r.ID,
		Aliases:  r.Aliases,
		Upstream: r.Upstream,
		Source:   SourceName,
		Kind:     kind,
		Summary:  r.Summary,
		Modified: r.Modified,
	}
	for _, sev := range r.Severity {
		out.Severity = append(out.Severity, advisory.Severity{Type: sev.Type, Score: sev.Score})
	}

	for _, ra := range r.Affected {
		// One advisory can carry entries for several ecosystems. Keeping a
		// foreign entry would feed its version strings to the wrong comparer.
		if ra.Package.Ecosystem != wantEcosystem || ra.Package.Name == "" {
			continue
		}
		aff := advisory.Affected{
			Ecosystem: ra.Package.Ecosystem,
			Name:      ra.Package.Name,
			Versions:  ra.Versions, // verbatim: OSV publishes non-canonical forms (D13)
		}
		for _, rr := range ra.Ranges {
			typ := advisory.RangeType(strings.ToUpper(rr.Type))
			// GIT ranges carry commit SHAs, not versions.
			if typ == advisory.RangeGit {
				continue
			}
			rng := advisory.Range{Type: typ}
			for _, re := range rr.Events {
				rng.Events = append(rng.Events, advisory.Event{
					Introduced:   re.Introduced,
					Fixed:        re.Fixed,
					LastAffected: re.LastAffected,
					Limit:        re.Limit,
				})
			}
			if len(rng.Events) > 0 {
				aff.Ranges = append(aff.Ranges, rng)
			}
		}
		if len(aff.Ranges) == 0 && len(aff.Versions) == 0 {
			continue // nothing left to match on
		}
		out.Affected = append(out.Affected, aff)
	}

	if len(out.Affected) == 0 {
		return advisory.Advisory{}, false, nil
	}
	return out, true, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/provider/... -v`
Expected: PASS, all nine test functions.

- [ ] **Step 5: Commit**

```bash
git add internal/provider
git commit -m "feat: convert OSV records, filtering withdrawn, malicious, and foreign ecosystems"
```

---

## Task 7: OSV fetch and the `db` commands

**Files:**
- Create: `internal/provider/osv/fetch.go`
- Create: `internal/provider/osv/fetch_test.go`
- Create: `internal/dbcmd/dbcmd.go`
- Create: `internal/dbcmd/dbcmd_test.go`
- Modify: `cmd/assay/main.go` — route `db update` and `db status`
- Modify: `cmd/assay/main_test.go` — extend the exit-code table

**Interfaces:**
- Consumes: `osv.Convert`, `provider.Provider`, `store.Create`, `store.Open`, `store.DefaultPath`, `store.Meta`, `store.Provenance`.
- Produces: `osv.New(ecosystems []string, baseURL string) *Provider`; `osv.Ecosystems` default slice; `dbcmd.Update(ctx, dbPath string, providers []provider.Provider, stdout, stderr io.Writer) int`; `dbcmd.Status(dbPath string, stdout, stderr io.Writer) int`.

Two behaviours the tests pin down:

- **`db update` builds into a temporary file and renames over the live database**, so a concurrent scan never observes a partial write. **On Windows, rename fails if the target is open** — close every handle before renaming, and do not assume POSIX semantics.
- **`db status` prints each provider's `DataAsOf`, not `BuiltAt`** (D12). It reports facts and does not judge staleness; age enforcement is deferred.

Expect roughly 244 MB of download for Go, npm, and PyPI. OSV has no server-side filtering, so most of npm's archive is discarded after parsing (D15).

- [ ] **Step 1: Write the failing test**

```go
package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

func zipWith(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFetch(t *testing.T) {
	body := zipWith(t, map[string]string{
		"GHSA-keep.json": `{"id":"GHSA-keep","affected":[{"package":{"name":"x","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}]}`,
		"GHSA-gone.json": `{"id":"GHSA-gone","withdrawn":"2024-01-01T00:00:00Z",
			"affected":[{"package":{"name":"y","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
		"MAL-2024-1.json": `{"id":"MAL-2024-1","affected":[{"package":{"name":"z","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Go/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Last-Modified", "Tue, 29 Jul 2026 00:00:00 GMT")
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Go"}, srv.URL)
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "GHSA-keep" {
		t.Fatalf("Fetch emitted %d advisories (%v), want only GHSA-keep", len(got), got)
	}
	if prov.Records != 1 {
		t.Errorf("Provenance.Records = %d, want 1", prov.Records)
	}
	// DataAsOf must come from the upstream response, not from time.Now (D12).
	if prov.DataAsOf.Year() != 2026 || prov.DataAsOf.Month() != 7 || prov.DataAsOf.Day() != 29 {
		t.Errorf("Provenance.DataAsOf = %v, want 2026-07-29 from Last-Modified", prov.DataAsOf)
	}
	if prov.Source == "" {
		t.Error("Provenance.Source is empty; the URL actually fetched must be recorded")
	}
}

func TestFetch_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := New([]string{"Go"}, srv.URL)
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Error("Fetch over a failing server = nil error, want error")
	}
}
```

```go
package dbcmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

type fakeProvider struct {
	name string
	advs []advisory.Advisory
}

func (f fakeProvider) Name() string { return f.name }

func (f fakeProvider) Fetch(_ context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	for _, a := range f.advs {
		if err := emit(a); err != nil {
			return store.Provenance{}, err
		}
	}
	return store.Provenance{
		Source:   "https://example.test/all.zip",
		DataAsOf: time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC),
		Records:  len(f.advs),
	}, nil
}

func TestUpdateThenStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", advs: []advisory.Advisory{{
		ID: "GHSA-x", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}

	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, []provider.Provider{p}, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := out.String()
	// Status reports upstream data time, which is the number that tells you
	// whether the data is stale (D12).
	if !strings.Contains(s, "2026-07-29") {
		t.Errorf("Status output missing DataAsOf:\n%s", s)
	}
	if !strings.Contains(s, "osv") {
		t.Errorf("Status output missing provider name:\n%s", s)
	}
}

func TestUpdateReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vulnerability.db")
	mk := func(id string) provider.Provider {
		return fakeProvider{name: "osv", advs: []advisory.Advisory{{
			ID: id, Source: "osv", Kind: advisory.KindVulnerability,
			Affected: []advisory.Affected{{Ecosystem: "Go", Name: "pkg"}},
		}}}
	}
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, []provider.Provider{mk("first")}, &out, &errOut); code != 0 {
		t.Fatalf("first Update = %d: %s", code, errOut.String())
	}
	if code := Update(context.Background(), path, []provider.Provider{mk("second")}, &out, &errOut); code != 0 {
		t.Fatalf("second Update = %d: %s", code, errOut.String())
	}

	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.Lookup("Go", "pkg")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "second" {
		t.Errorf("Lookup = %+v, want only the second build's advisory", got)
	}
	// No temporary file may survive a successful update.
	matches, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(matches) != 0 {
		t.Errorf("leftover temp files: %v", matches)
	}
}

func TestStatusWithoutDatabase(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Status(filepath.Join(t.TempDir(), "absent.db"), &out, &errOut)
	if code != 2 {
		t.Errorf("Status(absent) = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "db update") {
		t.Errorf("stderr should tell the user how to fix it:\n%s", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", out.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/provider/osv/ ./internal/dbcmd/ -v`
Expected: FAIL — `New`, `Update`, `Status` undefined.

- [ ] **Step 3: Write the implementation**

`internal/provider/osv/fetch.go`:

```go
package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// DefaultBaseURL is where OSV publishes one archive per ecosystem.
const DefaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// Ecosystems is slice 1's scope. Distro ecosystems arrive in slice 2, where
// their keys carry a release (D6).
var Ecosystems = []string{"Go", "npm", "PyPI"}

type Provider struct {
	ecosystems []string
	baseURL    string
	client     *http.Client
}

func New(ecosystems []string, baseURL string) *Provider {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Provider{
		ecosystems: ecosystems,
		baseURL:    strings.TrimRight(baseURL, "/"),
		// A generous timeout: npm's archive alone is ~203 MB.
		client: &http.Client{Timeout: 30 * time.Minute},
	}
}

func (p *Provider) Name() string { return SourceName }

func (p *Provider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	prov := store.Provenance{Source: p.baseURL}
	for _, eco := range p.ecosystems {
		u := fmt.Sprintf("%s/%s/all.zip", p.baseURL, url.PathEscape(eco))
		n, asOf, err := p.fetchOne(ctx, u, eco, emit)
		if err != nil {
			return store.Provenance{}, fmt.Errorf("fetch %s: %w", eco, err)
		}
		prov.Records += n
		// The oldest upstream timestamp wins: a database is only as fresh as
		// its stalest provider, and reporting the newest would hide that.
		if prov.DataAsOf.IsZero() || (!asOf.IsZero() && asOf.Before(prov.DataAsOf)) {
			prov.DataAsOf = asOf
		}
	}
	return prov, nil
}

func (p *Provider) fetchOne(ctx context.Context, u, ecosystem string, emit func(advisory.Advisory) error) (int, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, time.Time{}, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, time.Time{}, fmt.Errorf("GET %s: %s", u, resp.Status)
	}

	// DataAsOf comes from the server, not from the local clock (D12): a mirror
	// serving a stale snapshot must not look fresh because we fetched it today.
	var asOf time.Time
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			asOf = t.UTC()
		}
	}

	// archive/zip needs a ReaderAt, so the archive is buffered. Records are
	// still streamed to emit one at a time.
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, time.Time{}, err
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("open zip: %w", err)
	}

	var kept int
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return kept, asOf, fmt.Errorf("open %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return kept, asOf, fmt.Errorf("read %s: %w", f.Name, err)
		}
		a, ok, err := Convert(data, ecosystem)
		if err != nil {
			return kept, asOf, fmt.Errorf("convert %s: %w", f.Name, err)
		}
		if !ok {
			continue
		}
		if err := emit(a); err != nil {
			return kept, asOf, err
		}
		kept++
	}
	return kept, asOf, nil
}
```

`internal/dbcmd/dbcmd.go`:

```go
// Package dbcmd implements `assay db update` and `assay db status`.
package dbcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// Update rebuilds the database from every provider. It builds into a temporary
// file and renames over the live database, so a concurrent scan never observes
// a partial write.
func Update(ctx context.Context, dbPath string, providers []provider.Provider, stdout, stderr io.Writer) int {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		fmt.Fprintf(stderr, "error: create database directory: %v\n", err)
		return 2
	}
	tmp := dbPath + ".tmp"
	_ = os.Remove(tmp)

	w, err := store.Create(tmp)
	if err != nil {
		fmt.Fprintf(stderr, "error: create database: %v\n", err)
		return 2
	}

	meta := store.Meta{BuiltAt: time.Now().UTC(), Providers: map[string]store.Provenance{}}
	for _, p := range providers {
		fmt.Fprintf(stderr, "fetching %s…\n", p.Name())
		prov, err := p.Fetch(ctx, func(a advisory.Advisory) error { return w.Put(a) })
		if err != nil {
			w.Commit()
			os.Remove(tmp)
			fmt.Fprintf(stderr, "error: provider %s: %v\n", p.Name(), err)
			return 2
		}
		meta.Providers[p.Name()] = prov
	}
	if err := w.SetMeta(meta); err != nil {
		w.Commit()
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: write metadata: %v\n", err)
		return 2
	}
	// Close before renaming: on Windows a rename over an open file fails, and
	// assuming POSIX semantics here leaves a half-built database in place.
	if err := w.Commit(); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: close database: %v\n", err)
		return 2
	}
	if err := os.Rename(tmp, dbPath); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: replace database: %v\n", err)
		return 2
	}

	total := 0
	for _, p := range meta.Providers {
		total += p.Records
	}
	fmt.Fprintf(stdout, "database updated: %d advisories at %s\n", total, dbPath)
	return 0
}

// Status reports what is in the database and how current it is. It states
// facts and does not judge staleness — age enforcement is deferred, and the
// metadata it would need is already recorded.
func Status(dbPath string, stdout, stderr io.Writer) int {
	db, err := store.Open(dbPath)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSchemaMismatch) {
			fmt.Fprintf(stderr, "error: %v\n", err)
			fmt.Fprintln(stderr, "run `assay db update` to build it")
			return 2
		}
		fmt.Fprintf(stderr, "error: open database: %v\n", err)
		return 2
	}
	defer db.Close()

	m, err := db.Meta()
	if err != nil {
		fmt.Fprintf(stderr, "error: read metadata: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "database: %s\n", dbPath)
	fmt.Fprintf(stdout, "schema:   v%d\n", m.Schema)
	fmt.Fprintf(stdout, "built:    %s\n", m.BuiltAt.Format(time.RFC3339))
	fmt.Fprintln(stdout)

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PROVIDER\tDATA AS OF\tRECORDS\tSOURCE")
	// Sorted so the output is diffable across runs — map order is not.
	names := make([]string, 0, len(m.Providers))
	for name := range m.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := m.Providers[name]
		asOf := "unknown"
		if !p.DataAsOf.IsZero() {
			asOf = p.DataAsOf.Format("2006-01-02")
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", name, asOf, p.Records, p.Source)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "error: write status: %v\n", err)
		return 2
	}
	return 0
}
```

The import block for this file is:

```go
import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)
```

In `cmd/assay/main.go`, add a `db` case to the `run` switch:

```go
	case "db":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "error: db requires a subcommand (update, status)")
			return exitError
		}
		path, err := store.DefaultPath()
		if err != nil {
			fmt.Fprintf(stderr, "error: locate database: %v\n", err)
			return exitError
		}
		switch args[1] {
		case "update":
			return dbcmd.Update(context.Background(), path,
				[]provider.Provider{osv.New(osv.Ecosystems, "")}, stdout, stderr)
		case "status":
			return dbcmd.Status(path, stdout, stderr)
		default:
			fmt.Fprintf(stderr, "error: unknown db subcommand %q\n", args[1])
			return exitError
		}
```

and extend the usage string:

```
Commands:
  scan <target>   Scan an SBOM file, directory, or container image
  db update       Build or refresh the local vulnerability database
  db status       Show what is in the database and how current it is
  version         Print version information
  help            Show this help
```

- [ ] **Step 4: Run tests to verify they pass**

Add to `cmd/assay/main_test.go`'s existing table:

```go
		{"db without subcommand", []string{"db"}, exitError},
		{"db unknown subcommand", []string{"db", "bogus"}, exitError},
```

Run: `go test ./... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/osv/fetch.go internal/provider/osv/fetch_test.go internal/dbcmd cmd/assay
git commit -m "feat: add OSV fetch and the db update/status commands"
```

---

## Task 8: CycloneDX cataloger

**Files:**
- Create: `internal/cataloger/cyclonedx/cyclonedx.go`
- Create: `internal/cataloger/cyclonedx/testdata/small.cdx.json`
- Test: `internal/cataloger/cyclonedx/cyclonedx_test.go`

**Interfaces:**
- Consumes: `pkgmeta.Target`, `pkgmeta.Package`, `pkgmeta.Distro`, `pkgmeta.ParsePURL`, `pkgmeta.EcosystemForPURLType`.
- Produces: `cyclonedx.Parse(r io.Reader) (pkgmeta.Target, Stats, error)`; `cyclonedx.Stats{Components, Cataloged, SkippedNoPURL, SkippedUnsupportedEcosystem}`.

`Stats` exists because packages this stage cannot evaluate must be counted and reported, never folded silently into a clean result. In slice 1 every OS package in a container SBOM lands in `SkippedUnsupportedEcosystem`, and the report must say so.

The distro-release hazard applies here: matching an OS package needs `Alpine:v3.19`, which a purl does not carry. syft records it in CycloneDX properties (`syft:distro:id`, `syft:distro:versionID`), but that is a syft extension, not part of the CycloneDX specification. This task reads those properties when present and leaves `Target.Distro` nil when absent — it does not guess.

- [ ] **Step 1: Write the failing test**

`testdata/small.cdx.json`:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "type": "container",
      "name": "alpine",
      "properties": [
        {"name": "syft:distro:id", "value": "alpine"},
        {"name": "syft:distro:versionID", "value": "3.19"}
      ]
    }
  },
  "components": [
    {"type": "library", "name": "github.com/foo/bar", "version": "v1.2.3",
     "purl": "pkg:golang/github.com/foo/bar@v1.2.3"},
    {"type": "library", "name": "lodash", "version": "4.17.20",
     "purl": "pkg:npm/lodash@4.17.20"},
    {"type": "library", "name": "django", "version": "3.2",
     "purl": "pkg:pypi/django@3.2"},
    {"type": "library", "name": "apache2", "version": "2.4.54-r0",
     "purl": "pkg:apk/alpine/apache2@2.4.54-r0?arch=x86_64"},
    {"type": "library", "name": "mystery", "version": "1.0"}
  ]
}
```

```go
package cyclonedx

import (
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	f, err := os.Open("testdata/small.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	target, stats, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if stats.Components != 5 {
		t.Errorf("Components = %d, want 5", stats.Components)
	}
	// Go, npm, PyPI are supported in slice 1; apk is not (its ecosystem key
	// needs a release), and the last component has no purl at all.
	if stats.Cataloged != 3 {
		t.Errorf("Cataloged = %d, want 3", stats.Cataloged)
	}
	if stats.SkippedUnsupportedEcosystem != 1 {
		t.Errorf("SkippedUnsupportedEcosystem = %d, want 1", stats.SkippedUnsupportedEcosystem)
	}
	if stats.SkippedNoPURL != 1 {
		t.Errorf("SkippedNoPURL = %d, want 1", stats.SkippedNoPURL)
	}

	if len(target.Packages) != 3 {
		t.Fatalf("Packages = %d, want 3", len(target.Packages))
	}
	byName := map[string]int{}
	for i, p := range target.Packages {
		byName[p.Name] = i
	}
	gp := target.Packages[byName["github.com/foo/bar"]]
	if gp.Ecosystem != "Go" {
		t.Errorf("Go package ecosystem = %q, want Go", gp.Ecosystem)
	}
	if gp.Version != "v1.2.3" {
		t.Errorf("Go package version = %q, want v1.2.3 (verbatim, v intact)", gp.Version)
	}
	if target.Packages[byName["django"]].Ecosystem != "PyPI" {
		t.Errorf("django ecosystem = %q, want PyPI", target.Packages[byName["django"]].Ecosystem)
	}
}

func TestParse_DistroFromSyftProperties(t *testing.T) {
	f, err := os.Open("testdata/small.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	target, _, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if target.Distro == nil {
		t.Fatal("Distro = nil, want it read from syft properties")
	}
	if target.Distro.ID != "alpine" || target.Distro.VersionID != "3.19" {
		t.Errorf("Distro = %+v, want alpine 3.19", *target.Distro)
	}
}

func TestParse_NoDistroPropertiesLeavesNil(t *testing.T) {
	// syft:distro:* is a syft extension, not part of CycloneDX. An SBOM from
	// another tool may omit it, and guessing would be worse than admitting it.
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5",
	  "components":[{"type":"library","name":"lodash","version":"1.0",
	                 "purl":"pkg:npm/lodash@1.0"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatal(err)
	}
	if target.Distro != nil {
		t.Errorf("Distro = %+v, want nil when the properties are absent", *target.Distro)
	}
}

func TestParse_VersionFallsBackToComponentField(t *testing.T) {
	// A purl without a version is legal; the component's version field is the
	// fallback rather than treating the package as unversioned.
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5",
	  "components":[{"type":"library","name":"lodash","version":"4.17.20",
	                 "purl":"pkg:npm/lodash"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 || target.Packages[0].Version != "4.17.20" {
		t.Errorf("Packages = %+v, want version 4.17.20 from the component field", target.Packages)
	}
}

func TestParse_NotCycloneDX(t *testing.T) {
	if _, _, err := Parse(strings.NewReader(`{"spdxVersion":"SPDX-2.3"}`)); err == nil {
		t.Error("Parse(SPDX) = nil error, want error")
	}
	if _, _, err := Parse(strings.NewReader("{not json")); err == nil {
		t.Error("Parse(malformed) = nil error, want error")
	}
}
```

Add `"strings"` to the test file's imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cataloger/cyclonedx/ -v`
Expected: FAIL — `Parse` and `Stats` undefined.

- [ ] **Step 3: Write the implementation**

```go
// Package cyclonedx turns a CycloneDX SBOM into the normalized inventory.
//
// This is a Cataloger like any other: later slices add image and binary
// catalogers that produce the same pkgmeta.Target, so nothing downstream
// changes when they arrive.
package cyclonedx

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// Stats records what the cataloger could not use. Reported rather than
// discarded: a package silently dropped here is indistinguishable from a
// package with no vulnerabilities.
type Stats struct {
	Components                  int
	Cataloged                   int
	SkippedNoPURL               int
	SkippedUnsupportedEcosystem int
}

type bom struct {
	BOMFormat string `json:"bomFormat"`
	Metadata  struct {
		Component struct {
			Properties []property `json:"properties"`
		} `json:"component"`
	} `json:"metadata"`
	Components []component `json:"components"`
}

type component struct {
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	PURL       string     `json:"purl"`
	Properties []property `json:"properties"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func Parse(r io.Reader) (pkgmeta.Target, Stats, error) {
	var doc bom
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return pkgmeta.Target{}, Stats{}, fmt.Errorf("decode CycloneDX: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		return pkgmeta.Target{}, Stats{}, fmt.Errorf("not a CycloneDX document (bomFormat=%q)", doc.BOMFormat)
	}

	var (
		target pkgmeta.Target
		stats  Stats
	)
	target.Distro = distroFrom(doc.Metadata.Component.Properties)

	for _, c := range doc.Components {
		stats.Components++
		if c.PURL == "" {
			stats.SkippedNoPURL++
			continue
		}
		p, err := pkgmeta.ParsePURL(c.PURL)
		if err != nil {
			stats.SkippedNoPURL++
			continue
		}
		eco, ok := pkgmeta.EcosystemForPURLType(p.Type)
		if !ok {
			// Distro packages land here in slice 1: their ecosystem key needs
			// a release (D6) that a purl does not carry.
			stats.SkippedUnsupportedEcosystem++
			continue
		}
		version := p.Version
		if version == "" {
			version = c.Version
		}
		name := p.Name
		if p.Namespace != "" {
			name = p.Namespace + "/" + p.Name
		}
		target.Packages = append(target.Packages, pkgmeta.Package{
			Name:      name,
			Version:   version,
			Type:      p.Type,
			Ecosystem: eco,
			PURL:      c.PURL,
			Locations: []pkgmeta.Location{{Path: "sbom"}},
		})
		stats.Cataloged++
	}
	return target, stats, nil
}

// distroFrom reads syft's CycloneDX properties. These are a syft extension,
// not part of the CycloneDX specification, so an SBOM from another tool may
// omit them — in which case Distro stays nil rather than being guessed.
func distroFrom(props []property) *pkgmeta.Distro {
	var d pkgmeta.Distro
	for _, p := range props {
		switch p.Name {
		case "syft:distro:id":
			d.ID = p.Value
		case "syft:distro:versionID":
			d.VersionID = p.Value
		}
	}
	if d.ID == "" {
		return nil
	}
	return &d
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cataloger/... -v`
Expected: PASS, all five test functions.

- [ ] **Step 5: Commit**

```bash
git add internal/cataloger
git commit -m "feat: catalog CycloneDX SBOMs, counting what cannot be evaluated"
```

---

## Task 9: Matcher

**Files:**
- Create: `internal/matcher/matcher.go`
- Test: `internal/matcher/matcher_test.go`

**Interfaces:**
- Consumes: `store.Store`, `pkgmeta.Target`, `pkgmeta.Package`, `version.For`, `version.AffectsVersion`, `version.Evidence`, `version.ErrInvalid`, `advisory.Advisory`.
- Produces: `matcher.Finding{Package, Advisory, Evidence}`; `matcher.Skipped{Package, Reason}`; `matcher.Result{Findings, Skipped}`; `matcher.New(s store.Store) *Matcher`; `(*Matcher).Match(t pkgmeta.Target) (Result, error)`.

`Finding` carries `Evidence` because explainability is goal #1 (D10), and evidence that is not in the type ends up in log lines and effectively does not exist.

`Skipped` is the other half of the same idea. Every package the matcher cannot evaluate — no comparer for its ecosystem, an unparseable version, a malformed advisory bound — becomes a `Skipped` entry with a reason. **A comparison that errors must never become "not vulnerable".**

Findings are sorted before returning so output is deterministic and diffable.

- [ ] **Step 1: Write the failing test**

```go
package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// fakeStore keeps the matcher testable without a database.
type fakeStore struct {
	byKey map[string][]advisory.Advisory
}

func (f fakeStore) Lookup(ecosystem, name string) ([]advisory.Advisory, error) {
	return f.byKey[ecosystem+"\x00"+name], nil
}
func (f fakeStore) LookupBySource(ecosystem, name string) ([]advisory.Advisory, error) {
	return nil, nil
}
func (f fakeStore) Meta() (store.Meta, error) { return store.Meta{}, nil }
func (f fakeStore) Close() error              { return nil }

func advWithRange(id, eco, name, introduced, fixed string, rt advisory.RangeType) advisory.Advisory {
	return advisory.Advisory{
		ID:   id,
		Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{
			Ecosystem: eco,
			Name:      name,
			Ranges: []advisory.Range{{
				Type: rt,
				Events: []advisory.Event{
					{Introduced: introduced},
					{Fixed: fixed},
				},
			}},
		}},
	}
}

func pkg(name, version, eco string) pkgmeta.Package {
	return pkgmeta.Package{Name: name, Version: version, Ecosystem: eco}
}

func TestMatch_Hit(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00github.com/foo/bar": {
			advWithRange("GHSA-hit", "Go", "github.com/foo/bar", "0", "1.5.0", advisory.RangeSemver),
		},
	}}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("github.com/foo/bar", "v1.2.3", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Advisory.ID != "GHSA-hit" {
		t.Errorf("Advisory.ID = %q", f.Advisory.ID)
	}
	// Evidence must explain the match, not merely assert it (D10).
	if f.Evidence.Fixed != "1.5.0" {
		t.Errorf("Evidence.Fixed = %q, want 1.5.0", f.Evidence.Fixed)
	}
	if !strings.Contains(f.Evidence.Reason, "1.5.0") {
		t.Errorf("Evidence.Reason = %q, should name the boundary that decided it", f.Evidence.Reason)
	}
}

func TestMatch_Miss(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00github.com/foo/bar": {
			advWithRange("GHSA-fixed", "Go", "github.com/foo/bar", "0", "1.5.0", advisory.RangeSemver),
		},
	}}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("github.com/foo/bar", "v1.5.0", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %+v, want none: the fixed version is not affected", res.Findings)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("Skipped = %+v, want none: a clean miss is not a skip", res.Skipped)
	}
}

func TestMatch_UnparseableVersionIsSkippedNotClean(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00github.com/foo/bar": {
			advWithRange("GHSA-x", "Go", "github.com/foo/bar", "0", "1.5.0", advisory.RangeSemver),
		},
	}}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("github.com/foo/bar", "not-a-version", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %+v, want none", res.Findings)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d, want 1: an unparseable version must surface, not vanish", len(res.Skipped))
	}
	if res.Skipped[0].Reason == "" {
		t.Error("Skipped.Reason is empty")
	}
}

func TestMatch_UnsupportedEcosystemIsSkipped(t *testing.T) {
	res, err := New(fakeStore{}).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("apache2", "2.4.54-r0", "Alpine:v3.19")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d, want 1", len(res.Skipped))
	}
	if !strings.Contains(res.Skipped[0].Reason, "Alpine:v3.19") {
		t.Errorf("Skipped.Reason = %q, should name the ecosystem", res.Skipped[0].Reason)
	}
}

func TestMatch_DeduplicatesAdvisoryPerPackage(t *testing.T) {
	// The same advisory can be reachable more than once. One package plus one
	// advisory is one finding.
	a := advWithRange("GHSA-dupe", "Go", "x", "0", "2.0.0", advisory.RangeSemver)
	a.Affected = append(a.Affected, a.Affected[0])
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Go\x00x": {a, a}}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("x", "1.0.0", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("Findings = %d, want 1", len(res.Findings))
	}
}

func TestMatch_Deterministic(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00b": {advWithRange("GHSA-2", "Go", "b", "0", "9.0.0", advisory.RangeSemver)},
		"Go\x00a": {advWithRange("GHSA-1", "Go", "a", "0", "9.0.0", advisory.RangeSemver)},
	}}
	target := pkgmeta.Target{Packages: []pkgmeta.Package{
		pkg("b", "1.0.0", "Go"), pkg("a", "1.0.0", "Go"),
	}}
	first, err := New(s).Match(target)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(s).Match(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2", len(first.Findings))
	}
	for i := range first.Findings {
		if first.Findings[i].Advisory.ID != second.Findings[i].Advisory.ID {
			t.Fatal("Match is not deterministic across runs")
		}
	}
	if first.Findings[0].Package.Name != "a" {
		t.Errorf("Findings[0].Package = %q, want a (sorted)", first.Findings[0].Package.Name)
	}
}
```

Add `"github.com/kun9497/assay/internal/store"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/matcher/ -v`
Expected: FAIL — `New`, `Match`, `Finding` undefined.

- [ ] **Step 3: Write the implementation**

```go
// Package matcher decides whether an installed package is affected by a stored
// advisory, and records why.
package matcher

import (
	"fmt"
	"sort"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
	"github.com/kun9497/assay/internal/version"
)

type Finding struct {
	Package  pkgmeta.Package
	Advisory advisory.Advisory
	// Evidence is on the type, not in a log line, because explainability is
	// goal #1 and anything left to logging effectively does not exist (D10).
	Evidence version.Evidence
}

// Skipped is a package the matcher could not evaluate. It exists so that
// "we could not tell" never renders as "nothing found".
type Skipped struct {
	Package pkgmeta.Package
	Reason  string
}

type Result struct {
	Findings []Finding
	Skipped  []Skipped
}

type Matcher struct {
	store store.Store
}

func New(s store.Store) *Matcher { return &Matcher{store: s} }

func (m *Matcher) Match(t pkgmeta.Target) (Result, error) {
	var res Result

	for _, p := range t.Packages {
		cmp, ok := version.For(p.Ecosystem)
		if !ok {
			res.Skipped = append(res.Skipped, Skipped{
				Package: p,
				Reason:  fmt.Sprintf("no version comparer for ecosystem %q", p.Ecosystem),
			})
			continue
		}

		candidates, err := m.store.Lookup(p.Ecosystem, p.Name)
		if err != nil {
			// A store error is not a clean result. Fail the whole scan rather
			// than reporting a subset that reads as "fewer vulnerabilities".
			return Result{}, fmt.Errorf("lookup %s/%s: %w", p.Ecosystem, p.Name, err)
		}

		seen := make(map[string]bool, len(candidates))
		var skipReason string

		for _, a := range candidates {
			if seen[a.ID] {
				continue
			}
			for _, aff := range a.Affected {
				if aff.Ecosystem != p.Ecosystem || aff.Name != p.Name {
					continue
				}
				hit, ev, err := version.AffectsVersion(cmp, p.Version, aff)
				if err != nil {
					// Record the first reason and keep going: one malformed
					// advisory bound must not hide the rest.
					if skipReason == "" {
						skipReason = fmt.Sprintf("comparing %s: %v", p.Version, err)
					}
					continue
				}
				if hit {
					seen[a.ID] = true
					res.Findings = append(res.Findings, Finding{Package: p, Advisory: a, Evidence: ev})
					break
				}
			}
		}

		if skipReason != "" && !anyFindingFor(res.Findings, p) {
			res.Skipped = append(res.Skipped, Skipped{Package: p, Reason: skipReason})
		}
	}

	sortFindings(res.Findings)
	sortSkipped(res.Skipped)
	return res, nil
}

func anyFindingFor(fs []Finding, p pkgmeta.Package) bool {
	for _, f := range fs {
		if f.Package.Name == p.Name && f.Package.Ecosystem == p.Ecosystem {
			return true
		}
	}
	return false
}

// Sorting keeps output deterministic and diffable, which is design goal #3.
func sortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Package.Ecosystem != b.Package.Ecosystem {
			return a.Package.Ecosystem < b.Package.Ecosystem
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		return a.Advisory.ID < b.Advisory.ID
	})
}

func sortSkipped(ss []Skipped) {
	sort.Slice(ss, func(i, j int) bool {
		a, b := ss[i], ss[j]
		if a.Package.Ecosystem != b.Package.Ecosystem {
			return a.Package.Ecosystem < b.Package.Ecosystem
		}
		return a.Package.Name < b.Package.Name
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/matcher/ -v`
Expected: PASS, all six test functions.

- [ ] **Step 5: Commit**

```bash
git add internal/matcher
git commit -m "feat: match packages against advisories, recording evidence and skips"
```

---

## Task 10: Table report and `scan` wiring

**Files:**
- Create: `internal/report/table.go`
- Test: `internal/report/table_test.go`
- Create: `internal/scancmd/scancmd.go`
- Test: `internal/scancmd/scancmd_test.go`
- Modify: `cmd/assay/main.go` — replace the unimplemented `scan` stub
- Modify: `cmd/assay/main_test.go` — the "scan not implemented" row changes meaning

**Interfaces:**
- Consumes: `matcher.Result`, `matcher.Finding`, `matcher.Skipped`, `cyclonedx.Parse`, `cyclonedx.Stats`, `store.Open`, `store.DefaultPath`.
- Produces: `report.Table(w io.Writer, res matcher.Result, cat cyclonedx.Stats) error`; `scancmd.Run(dbPath, target string, stdout, stderr io.Writer) int`.

Scope note: `--fail-on` is slice 4. Slice 1 therefore exits **0** even when findings are printed — there is no gate yet for anything to be "at or above". The exit-2 paths are the ones that matter here: a missing database, an unreadable SBOM, a store error.

The summary line is not decoration. It carries the counts that keep a partial scan from reading as a clean one: how many packages were cataloged, how many were skipped by the cataloger, and how many were skipped by the matcher.

- [ ] **Step 1: Write the failing test**

```go
package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/version"
)

func TestTable_Findings(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "github.com/foo/bar", Version: "v1.2.3", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-hit", Summary: "Code injection"},
		Evidence: version.Evidence{Introduced: "0", Fixed: "1.5.0", Reason: "below the fix 1.5.0"},
	}}}
	var buf bytes.Buffer
	if err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"github.com/foo/bar", "v1.2.3", "GHSA-hit", "1.5.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestTable_SkippedCountsAreVisible(t *testing.T) {
	// A scan that could not evaluate 40 packages must not read as clean.
	res := matcher.Result{Skipped: []matcher.Skipped{{
		Package: pkgmeta.Package{Name: "apache2", Version: "2.4.54-r0", Ecosystem: "Alpine:v3.19"},
		Reason:  "no version comparer for ecosystem \"Alpine:v3.19\"",
	}}}
	var buf bytes.Buffer
	if err := Table(&buf, res, cyclonedx.Stats{
		Components: 42, Cataloged: 1, SkippedUnsupportedEcosystem: 40, SkippedNoPURL: 1,
	}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "40") {
		t.Errorf("cataloger skip count missing from summary:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "skipped") {
		t.Errorf("summary never uses the word skipped:\n%s", out)
	}
}

func TestTable_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, matcher.Result{}, cyclonedx.Stats{Components: 3, Cataloged: 3}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(strings.ToLower(out), "no known vulnerabilities") {
		t.Errorf("clean scan should say so plainly:\n%s", out)
	}
}

func TestTable_Deterministic(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		{Package: pkgmeta.Package{Name: "a", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-1"}},
		{Package: pkgmeta.Package{Name: "b", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-2"}},
	}}
	var first, second bytes.Buffer
	if err := Table(&first, res, cyclonedx.Stats{}); err != nil {
		t.Fatal(err)
	}
	if err := Table(&second, res, cyclonedx.Stats{}); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Error("Table output is not deterministic")
	}
}
```

```go
package scancmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_MissingDatabase(t *testing.T) {
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o600)

	var out, errOut bytes.Buffer
	code := Run(filepath.Join(t.TempDir(), "absent.db"), sbom, &out, &errOut)
	if code != 2 {
		t.Errorf("Run without a database = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "db update") {
		t.Errorf("stderr should point at the fix:\n%s", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", out.String())
	}
}

func TestRun_MissingSBOM(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(filepath.Join(t.TempDir(), "absent.db"),
		filepath.Join(t.TempDir(), "absent.cdx.json"), &out, &errOut)
	if code != 2 {
		t.Errorf("Run with a missing SBOM = %d, want 2", code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ ./internal/scancmd/ -v`
Expected: FAIL — `Table` and `Run` undefined.

- [ ] **Step 3: Write the implementation**

`internal/report/table.go`:

```go
// Package report renders findings. Output is deterministic and diffable, which
// is design goal #3 — a scanner whose output churns cannot be used in CI.
package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
)

func Table(w io.Writer, res matcher.Result, cat cyclonedx.Stats) error {
	if len(res.Findings) == 0 {
		fmt.Fprintln(w, "No known vulnerabilities found.")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PACKAGE\tVERSION\tECOSYSTEM\tADVISORY\tFIXED IN")
		for _, f := range res.Findings {
			fixed := f.Evidence.Fixed
			if fixed == "" {
				fixed = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
				f.Package.Name, f.Package.Version, f.Package.Ecosystem, f.Advisory.ID, fixed)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	// The summary is what keeps a partial scan from reading as a clean one.
	skipped := cat.SkippedNoPURL + cat.SkippedUnsupportedEcosystem + len(res.Skipped)
	fmt.Fprintf(w, "\n%d package(s) scanned, %d finding(s), %d skipped\n",
		cat.Cataloged, len(res.Findings), skipped)

	if skipped > 0 {
		fmt.Fprintln(w, "\nSkipped:")
		if cat.SkippedUnsupportedEcosystem > 0 {
			fmt.Fprintf(w, "  %d package(s) in an unsupported ecosystem\n",
				cat.SkippedUnsupportedEcosystem)
		}
		if cat.SkippedNoPURL > 0 {
			fmt.Fprintf(w, "  %d component(s) without a usable purl\n", cat.SkippedNoPURL)
		}
		for _, s := range res.Skipped {
			fmt.Fprintf(w, "  %s %s: %s\n", s.Package.Name, s.Package.Version, s.Reason)
		}
	}
	return nil
}
```

`internal/scancmd/scancmd.go`:

```go
// Package scancmd implements `assay scan`.
package scancmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/store"
)

// Run scans an SBOM file. Slice 1 has no --fail-on, so a completed scan exits
// 0 even with findings; the exit-2 paths are what matter here.
func Run(dbPath, target string, stdout, stderr io.Writer) int {
	f, err := os.Open(target)
	if err != nil {
		fmt.Fprintf(stderr, "error: open %s: %v\n", target, err)
		return 2
	}
	defer f.Close()

	inventory, cat, err := cyclonedx.Parse(f)
	if err != nil {
		fmt.Fprintf(stderr, "error: parse %s: %v\n", target, err)
		return 2
	}

	db, err := store.Open(dbPath)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSchemaMismatch) {
			fmt.Fprintf(stderr, "error: %v\n", err)
			fmt.Fprintln(stderr, "run `assay db update` to build it")
			return 2
		}
		fmt.Fprintf(stderr, "error: open database: %v\n", err)
		return 2
	}
	defer db.Close()

	res, err := matcher.New(db).Match(inventory)
	if err != nil {
		fmt.Fprintf(stderr, "error: match: %v\n", err)
		return 2
	}
	if err := report.Table(stdout, res, cat); err != nil {
		fmt.Fprintf(stderr, "error: write report: %v\n", err)
		return 2
	}
	return 0
}
```

In `cmd/assay/main.go`, replace the `scan` stub:

```go
// scan is the pipeline entry point: parse the target into an inventory, match
// it against the local database, and report.
func scan(target string, stdout, stderr io.Writer) int {
	path, err := store.DefaultPath()
	if err != nil {
		fmt.Fprintf(stderr, "error: locate database: %v\n", err)
		return exitError
	}
	return scancmd.Run(path, target, stdout, stderr)
}
```

- [ ] **Step 4: Run tests to verify they pass**

The existing `main_test.go` row `{"scan not implemented", []string{"scan", "alpine:3.19"}, exitError}` still expects 2, and still gets it — `alpine:3.19` is not a readable file. Rename it so the assertion matches its new reason:

```go
		{"scan of an unreadable target", []string{"scan", "alpine:3.19"}, exitError},
```

Run: `go test ./... -v`
Expected: PASS across every package.

- [ ] **Step 5: End-to-end check against real data**

This is the point of the slice. Run it for real:

```bash
make build
./bin/assay db update
./bin/assay db status
syft alpine:3.19 -o cyclonedx-json > /tmp/alpine.cdx.json
./bin/assay scan /tmp/alpine.cdx.json
```

Expected: `db status` lists `osv` with a `DATA AS OF` date and a five-figure record count. The alpine scan reports **0 findings and a large skipped count** — every apk package lands in the unsupported-ecosystem bucket in slice 1, which is the honest answer, not a clean bill of health.

For a scan that should actually find something, generate an SBOM from a Go project with known-vulnerable dependencies:

```bash
syft dir:/path/to/some/go/project -o cyclonedx-json > /tmp/go.cdx.json
./bin/assay scan /tmp/go.cdx.json
grype /tmp/go.cdx.json
```

Compare the two outputs. Exact agreement is not expected — the data sources differ — but **a large divergence means the matcher is wrong**. Investigate before committing.

- [ ] **Step 6: Commit**

```bash
git add internal/report internal/scancmd cmd/assay
git commit -m "feat: render findings as a table and wire up assay scan"
```

---

## Self-review

Run before handing the plan off.

**Spec coverage.** Every slice 1 completion criterion in the roadmap maps to a task: `db update` and `db status` (Task 7), CycloneDX ingestion (Task 8), OSV provider and bbolt store (Tasks 5–7), per-ecosystem comparison and range matching (Tasks 2–4), table output (Task 10), missing-database exit 2 (Tasks 7 and 10), comparer table tests (Tasks 2–3), grype differential (Task 10 Step 5).

**Deferred, deliberately.** `--fail-on` and `--fail-on-unknown`, severity banding, JSON/SARIF, and explain mode are slice 4. Severity vectors are stored from Task 6 so slice 4 needs no rebuild (D13). `LookupBySource` and `Package.Source` exist but have no producer until slice 2 — the interface is fixed now so its first real consumer does not change it.

**Type consistency.** `Comparer.Compare(a, b string) (int, error)` is used identically in Tasks 2, 3, 4, and 9. `store.Store` as consumed by the matcher matches what `Bolt` implements. `version.Evidence` is produced in Task 4, carried through Task 9, and rendered in Task 10. `cyclonedx.Stats` is produced in Task 8 and consumed in Task 10.

**Known gap.** `Advisory.Kind` is written by the OSV provider and read by nothing in slice 1. That is intended (D15): storing it now makes enabling malicious-package reports a filter change rather than a database rebuild.

