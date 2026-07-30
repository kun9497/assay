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
		// Non-ASCII: Go's (?i) would fold these into ASCII if not rejected first
		"１.０", "٣.٤", "1.0+K",
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

func intro(v string) advisory.Event  { return advisory.Event{Introduced: v} }
func fixed(v string) advisory.Event  { return advisory.Event{Fixed: v} }
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
			continue // an unorderable entry in the list is not a reason to fail the whole check
		}
		if cmp == 0 {
			return true, Evidence{
				Reason: fmt.Sprintf("version %s is listed as affected", v),
			}, nil
		}
	}
	return false, Evidence{}, nil
}

// InRange walks an OSV range's events in order, tracking whether v is currently
// inside an open window. Events are half-open [introduced, fixed) with the
// exception of last_affected, which is inclusive.
func InRange(c Comparer, v string, r advisory.Range) (bool, Evidence, error) {
	// GIT ranges carry commit SHAs, not versions. Skipping is correct; parsing
	// would error on data that was never meant for a Comparer.
	if r.Type == advisory.RangeGit {
		return false, Evidence{}, nil
	}

	var (
		inside bool
		ev     Evidence
	)
	ev.RangeType = r.Type

	for _, e := range r.Events {
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
			} else if inside {
				ev.Fixed = e.Fixed
			}

		case e.LastAffected != "":
			cmp, err := c.Compare(v, e.LastAffected)
			if err != nil {
				return false, Evidence{}, fmt.Errorf("compare %q to last_affected %q: %w", v, e.LastAffected, err)
			}
			if inside && cmp > 0 {
				inside = false // inclusive upper bound: equal is still affected
			} else if inside {
				ev.LastAffected = e.LastAffected
			}
		}
	}

	if inside {
		ev.Reason = describe(v, ev)
	}
	return inside, ev, nil
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
