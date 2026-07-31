# Slice 2a — Distro Matching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `assay scan alpine.cdx.json` report real Alpine findings — apk version
ordering, release-qualified ecosystem keys, `Target.Distro`, and source-package indirect
matching — without writing a single line of container-reading code.

**Architecture:** The syft-generated CycloneDX SBOM of an Alpine image already carries
everything the matcher needs: an `operating-system` component with `syft:distro:*`
properties, apk purls, and `syft:metadata:originPackage` for the source package. Slice 2a
consumes those. Slice 2b replaces the SBOM with layers we read ourselves; nothing in this
slice is thrown away when it does, because the boundary is the `Cataloger` interface.

**Tech Stack:** Go 1.26, stdlib only plus the existing `go.etcd.io/bbolt`. No new
dependencies. `CGO_ENABLED=0`.

---

## Why this is a slice of its own

The roadmap defines slice 2 as `assay scan alpine:3.19` — registry pull through to matching.
Splitting it puts all of the design risk first and none of the plumbing:

| Roadmap's stated design risk | Needs a registry client? |
|---|---|
| `Target.Distro` (D7) | no |
| Release-qualified ecosystem keys (D6) | no |
| `Package.Source` indirect matching (D8) | no |
| apk `Comparer` (D9) | no |
| Layer provenance in `Location` | no — syft emits `syft:location:0:layerID` |

Registry pull, layer extraction, whiteout handling, and `/lib/apk/db/installed` parsing
validate none of them. They are slice 2b, recorded in `docs/deferred-decisions.md` as the
immediate follow-on rather than a deferral.

**Ordering is not a preference.** 2a is a prerequisite for 2b: an image read perfectly but
matched against no distro ecosystem produces zero findings.

---

## Measured inputs

Everything below was measured on 2026-07-30 against the live OSV bucket and the slice-1
alpine SBOM. Do not re-derive; do not replace with estimates.

**OSV Alpine data**

| Fact | Value |
|---|---|
| Versioned ecosystem keys | `Alpine:v3.2` … `Alpine:v3.20`, plus an unversioned `Alpine/` prefix |
| `ecosystems.txt` lists them? | **No** — it lists `Alpine` only, no versioned keys, 52 entries with zero colons |
| Discoverable via | `https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o?delimiter=/&prefix=Alpine` → `prefixes[]` |
| `Alpine:v3.19/all.zip` | 6.24 MB, 2,361 records |
| **All 19 releases** | **64.7 MB** — v3.2 0.63 MB rising monotonically to v3.20 6.43 MB |
| Record ID prefixes | 100% `CVE-*` — no `GHSA-*`, no `MAL-*` |
| Withdrawn records in v3.19 | 18 (D16 already drops them) |
| Affected entries carrying `?arch=source` | 32,069 of 33,589 (95%) |
| Alpine affected entries with `ranges` | 2,436 of 2,436 — **none are `versions`-only** |

> ### CORRECTION (2026-07-31, found by Task 6's end-to-end run)
>
> **Everything in this subsection about fetching per-release prefixes is wrong.**
> The versioned `Alpine:vX.Y/` prefixes are a **frozen legacy export**: every one
> carries `Last-Modified: 2024-10-09`, the newest record inside is `modified`
> 2024-10-09, and they stop at v3.20.
>
> The unversioned **`Alpine/` prefix is the current export** — `Last-Modified`
> 2026-07-30, 3.98 MB, 4,405 records — and the ecosystem keys *inside* it are
> still release-qualified (`Alpine:v3.2` … `Alpine:v3.24`, 23 releases), so D6
> holds. The prefix is a file path, not an ecosystem key. This plan conflated
> the two and therefore filtered out the only archive worth fetching.
>
> Measured consequence: an `alpine:3.19` scan against a database built from the
> versioned prefixes reports **0 findings** where grype reports 10 distro
> findings. None of `CVE-2024-58251`, `CVE-2025-46394`, `CVE-2026-40200`,
> `CVE-2026-6042` exists in the frozen export; all are in `Alpine/`. The matcher
> was right — busybox `1.36.1-r20` genuinely postdates every fixed version the
> frozen data knows about (newest `1.36.1-r19`). The data was 21 months stale.
>
> `Alpine/` is effectively a superset: 43,145 affected entries against the
> frozen v3.16+v3.19 union's 25,922, with only **74** entries (0.29%, all
> 2019-era, e.g. `CVE-2019-16062` elfutils) present in the frozen export and
> absent from the current one. Those are treated as upstream corrections, not
> as coverage to preserve — a stale export does not outrank a live one.
>
> **Also wrong: the ID and alias shape.** Alpine records are `ALPINE-CVE-*`, and
> on all 4,405 of them `aliases` is **empty** while `upstream` carries the plain
> CVE. Slice 1's measurement was the mirror image (Go: `upstream` empty on all
> 8,510, `aliases` carries the CVE), which is why D3 requires reading both. The
> report's ALIASES column reads only `Advisory.Aliases`, so
> `assay scan … | grep CVE-2025-46394` finds nothing — the exact failure that
> column was added to prevent.
>
> **Revised design.** Fetch the single `Alpine/` archive; drop release
> discovery entirely, since one archive carries every release. That is 3.98 MB
> rather than 64.7 MB, current rather than frozen, and covers four releases the
> per-release path cannot reach. What replaces the discovery hard-failure is a
> check that the archive yielded at least one `Alpine:*` ecosystem — the same
> guarantee, one layer in.

**Fetch all 19, and say what it costs.** `assay` builds its own database rather than
downloading a prebuilt one (D14, and "Publishing the database as an OCI artifact" is a
recorded deferral), so this 64.7 MB is a real cost paid by every user on every `db update` —
on top of the ~244 MB the language ecosystems already cost, a 27% increase.

Fetch them all anyway. The alternative — a "recent releases only" default — trades bandwidth
for the project's worst failure mode: scanning an Alpine 3.14 image against a database that
never heard of `Alpine:v3.14` reports zero findings and exits 0. Old images are also exactly
where the findings are. On-disk growth is far below 64.7 MB because the same CVE record
appears in many release archives and the store is keyed by advisory ID, so `Put` dedupes
them; measure the real figure in Task 6 rather than predicting it here.

If bandwidth turns out to matter, the fix is a `--ecosystem` filter on `db update`, not a
quieter default. Raise it as a decision then; do not add it in this slice.

**Each release's archive is not a superset of the others.** `Alpine:v3.19/all.zip` contains
2,171 of the 2,242 `Alpine:v3.16` affected entries; **71 are missing** (e.g. `CVE-2019-5882`
irssi, `CVE-2018-5996` p7zip). Fetching one release and reusing its cross-release entries
would produce silent false negatives. Every release you claim to support must be fetched.

**apk version strings** — 10,444 distinct values in `Alpine:v3.19/all.zip`:

| Shape (digits → `N`) | Count |
|---|---|
| `N.N.N-rN` | 7,565 |
| `N.N-rN` | 1,488 |
| `N.N.N.N-rN` | 431 |
| `N.N_pN-rN` | 388 |
| `N.N.N_pN-rN` | 205 |
| `N-rN` | 61 |
| `N.N.N_rcN-rN` | 37 |
| `N.N_preN-rN` | 27 |
| `N.N.N` (no revision at all) | 11 |
| single-letter, e.g. `N.N.Nb-rN` | 16 + 13 + 12 + 12 + 12 + 10 + … |

Suffix tokens present: `_p` 594 · `_rc` 59 · `_pre` 44 · `_beta` 11 · `_git` 1.

**The slice-1 alpine SBOM** (`mirror.gcr.io/library/alpine:3.19`, 17 components):

| What we need | Where it is | Value |
|---|---|---|
| `Target.Distro` (D7) | `components[16]`, `"type": "operating-system"` | `syft:distro:id=alpine`, `syft:distro:versionID=3.19.9`, `syft:distro:prettyName=Alpine Linux v3.19` |
| Package identity | `purl` | `pkg:apk/alpine/alpine-baselayout@3.4.3-r2?arch=x86_64&distro=alpine-3.19.9` |
| `Package.Source` (D8) | `syft:metadata:originPackage` | present on 15 of 17 |
| Layer provenance | `syft:location:0:layerID` | `sha256:0b44b215…` |

**D8 is load-bearing on this exact image.** Nine of fifteen origin packages differ from the
binary name:

```
alpine-baselayout-data ← alpine-baselayout      musl-utils   ← musl
busybox-binsh          ← busybox                scanelf      ← pax-utils
ca-certificates-bundle ← ca-certificates        ssl_client   ← busybox
libc-utils             ← libc-dev
libcrypto3             ← openssl
libssl3                ← openssl
```

A single `openssl` advisory is unreachable from **both** `libssl3` and `libcrypto3` without
it. That is the silent-false-negative class D8 exists to prevent, and it is not
hypothetical — it is 2 of the 15 packages in the smallest mainstream base image.

---

## Global Constraints

- Go 1.26. Stdlib only; the sole third-party dependency stays `go.etcd.io/bbolt v1.5.0`.
  Adding another is a decision that must be raised, not made inside a task.
- `CGO_ENABLED=0`. `make test` fails without a C toolchain; use `go test ./...` locally.
- **No network on the scan path** (D14). Only `assay db update` reaches out.
- Exit codes are contract: `0` clean, `1` findings at/above `--fail-on`, `2` cannot run or
  cannot be trusted; precedence `2 > 1 > 0` (D11). Slice 2a adds no `--fail-on`, so a
  completed scan still exits 0 — but a scan that evaluates nothing must still exit 2.
- **Ecosystem keys carry the release** (D6): `Alpine:v3.19`, never `Alpine`.
- **The distro lives on `Target`, not `Package`** (D7).
- **`Package.Source` is load-bearing** (D8). Dropping it produces false negatives.
- **Version comparison stays per-ecosystem** (D9). `Compare(a, b string) (int, error)`; an
  unparseable version is `ErrInvalid` and the package is reported as skipped, never treated
  as not-vulnerable.
- **`Finding` carries `Evidence`** (D10). Explainability is goal #1.
- Unknown severity is its own band (D17); never coerce to `low`.
- Every key path normalizes through `pkgmeta.NormalizeName`. For apk ecosystems it is a
  no-op today — that is not a licence to skip it, since the store and matcher must agree.
- Comments explain *why*, matching the register already in `main.go` and `matcher.go`.
- Docs are bilingual (`X.md` + `X.ko.md`, English canonical, same commit). **Plans are
  exempt** — this file is English only.

---

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `internal/version/apk.go` | apk-tools version ordering |
| `internal/version/apk_test.go` | the table that catches false negatives |
| `internal/pkgmeta/distro.go` | `Distro` type; `/etc/os-release`-shaped fields → ecosystem key |
| `internal/pkgmeta/distro_test.go` | key derivation, including the cases that must *fail* |
| `internal/provider/osv/alpine.go` | Alpine release discovery |
| `internal/provider/osv/alpine_test.go` | discovery against a fake bucket listing |

**Modified**

| File | Change |
|---|---|
| `internal/pkgmeta/package.go` | `Target.Distro` field |
| `internal/pkgmeta/purl.go` | `apk` → release-qualified ecosystem, via the target's distro |
| `internal/version/version.go` | register `APK{}` under Alpine keys |
| `internal/cataloger/cyclonedx/cyclonedx.go` | parse the `operating-system` component; apk packages; `Source` from `originPackage` |
| `internal/matcher/matcher.go` | look up by source name as well as binary name (D8); record which in `Evidence` |
| `internal/report/table.go` | show the source package when it is what matched |
| `internal/dbcmd/dbcmd.go` | wire Alpine ecosystems into `db update` |
| `internal/provider/osv/fetch.go` | per-release fetch |

---

## Task 1: apk version comparison

**This is the task with the highest false-negative risk in the slice.** Write it in the main
loop, review the table line by line, and do not delegate the implementation. The rules below
come from `apk-tools/src/version.c`; cite it rather than reasoning from examples.

**Files:**
- Create: `internal/version/apk.go`
- Create: `internal/version/apk_test.go`
- Modify: `internal/version/version.go`

**Interfaces:**
- Consumes: `Comparer`, `ErrInvalid` from `internal/version/version.go`
- Produces: `type APK struct{}` implementing `Compare(a, b string) (int, error)`

### The algorithm, from apk-tools

A version is a token stream:

```
initial_digit ( '.' digit )* letter? ( '_' suffix number? )* ( '~' hash )? ( '-r' number )?
```

Token kinds, **in apk-tools' declaration order** — the order is load-bearing:

```
INITIAL_DIGIT=0  DIGIT=1  LETTER=2  SUFFIX=3  SUFFIX_NO=4
COMMIT_HASH=5    REVISION_NO=6      END=7     INVALID=8
```

Suffixes, in ascending order, with `""` (none) in the middle:

```
alpha < beta < pre < rc < "" < cvs < svn < git < hg < p
                          ^ index 4
```

So `1.0_rc1 < 1.0 < 1.0_p1`. **Getting the post-release half backwards makes every `_p`
package silently not-vulnerable** — 594 version strings in v3.19 alone carry `_p`.

Comparison walks both token streams in parallel:

1. Same kind → compare values and continue.
   - digits: numeric, **unless either side has a leading zero**, in which case raw string
     comparison ("similar to the Gentoo spec", per the source comment).
   - letter: byte value. suffix: index in the table above. suffix number / revision:
     numeric. commit hash: string.
2. Kinds differ (one stream ended, or the shapes diverge):
   - if `a`'s token is a `SUFFIX` below `""` → `a` is less
   - if `b`'s token is a `SUFFIX` below `""` → `b` is less
   - otherwise **the higher token kind is the lower version** (`END=7` is the highest, so a
     version that ran out is less than one that continues)

That last rule produces a genuinely surprising result that must be in the table:
`1.0 < 1.0-r0`, because `END(7) > REVISION_NO(6)`.

- [ ] **Step 1: Write the failing test**

`internal/version/apk_test.go`:

```go
package version

import "testing"

// The ordering rules come from apk-tools/src/version.c. Cases are grouped by
// the rule they exercise so that a failure names the rule, not just a pair.
func TestAPKCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		why  string
	}{
		// Plain numeric ordering, the 7,565-case majority shape.
		{"1.2.3-r0", "1.2.3-r0", 0, "identical"},
		{"1.2.3-r0", "1.2.3-r1", -1, "revision breaks the tie"},
		{"1.2.3-r2", "1.2.3-r10", -1, "revision is numeric, not lexical"},
		{"1.2.3-r0", "1.2.4-r0", -1, "patch component"},
		{"1.2.9-r0", "1.2.10-r0", -1, "digit runs are numeric, not lexical"},
		{"1.9.0-r0", "1.10.0-r0", -1, "minor component is numeric too"},

		// Differing component counts. END is the highest token kind, so the
		// shorter version is the lower one.
		{"1.2", "1.2.1", -1, "shorter runs out first"},
		{"1.2.0", "1.2", 1, "an explicit .0 still outranks nothing"},
		{"1-r0", "1.0-r0", -1, "one component vs two"},

		// The surprising one: a missing revision is lower than -r0, because
		// END(7) outranks REVISION_NO(6) and a higher kind means a lower version.
		{"1.0", "1.0-r0", -1, "no revision sorts below -r0"},

		// Pre-release suffixes sort BELOW the bare version.
		{"1.0_alpha1", "1.0", -1, "alpha is a pre-release"},
		{"1.0_beta1", "1.0", -1, "beta is a pre-release"},
		{"1.0_pre1", "1.0", -1, "pre is a pre-release"},
		{"1.0_rc1", "1.0", -1, "rc is a pre-release"},
		{"1.0_alpha1", "1.0_beta1", -1, "alpha < beta"},
		{"1.0_beta1", "1.0_pre1", -1, "beta < pre"},
		{"1.0_pre1", "1.0_rc1", -1, "pre < rc"},
		{"1.0_rc1", "1.0_rc2", -1, "suffix number is numeric"},

		// Post-release suffixes sort ABOVE the bare version. Reversing this
		// half is a silent false negative on 594 v3.19 version strings.
		{"1.0", "1.0_p1", -1, "p is a post-release"},
		{"1.0_rc1", "1.0_p1", -1, "pre-release < bare < post-release"},
		{"1.0_cvs1", "1.0_svn1", -1, "cvs < svn"},
		{"1.0_svn1", "1.0_git1", -1, "svn < git"},
		{"1.0_git1", "1.0_hg1", -1, "git < hg"},
		{"1.0_hg1", "1.0_p1", -1, "hg < p"},
		{"1.0_p1", "1.0_p2", -1, "post-release number is numeric"},

		// Single trailing letter, the openssl shape (1.1.1l-r0).
		{"1.1.1", "1.1.1a", -1, "a letter outranks no letter"},
		{"1.1.1a", "1.1.1b", -1, "letters compare by byte"},
		{"1.1.1k-r0", "1.1.1l-r0", -1, "the real openssl case"},
		{"1.1.1l-r0", "1.1.1l-r1", -1, "revision still breaks the tie"},

		// Leading zeros switch to string comparison, per the source comment.
		{"1.01", "1.1", -1, "leading zero forces string sort: '01' < '1'"},
		{"1.001", "1.01", -1, "string sort again: '001' < '01'"},
		{"1.10", "1.9", 1, "no leading zero, so numeric: 10 > 9"},

		// Real pairs lifted from Alpine:v3.19 advisories.
		{"2.1.23-r0", "2.1.26-r7", -1, "cyrus-sasl, CVE-2013-4122"},
		{"3.1.4-r5", "3.1.4-r6", -1, "openssl revision bump"},
		{"1.36.1-r15", "1.36.1-r2", 1, "busybox: r15 > r2, numerically"},
	}

	var c APK
	for _, tt := range tests {
		got, err := c.Compare(tt.a, tt.b)
		if err != nil {
			t.Errorf("Compare(%q, %q) unexpected error: %v", tt.a, tt.b, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (%s)", tt.a, tt.b, got, tt.want, tt.why)
		}
		// Antisymmetry is a property of the ordering, not an extra case: if it
		// does not hold, the comparator cannot be used for sorting either.
		back, err := c.Compare(tt.b, tt.a)
		if err != nil {
			t.Errorf("Compare(%q, %q) unexpected error: %v", tt.b, tt.a, err)
			continue
		}
		if back != -tt.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry with %s)",
				tt.b, tt.a, back, -tt.want, tt.why)
		}
	}
}

// D9: an unparseable version must surface as ErrInvalid so the package is
// reported as skipped. Returning "not vulnerable" for garbage is a miss.
func TestAPKCompare_Invalid(t *testing.T) {
	bad := []string{
		"",           // empty
		"-r1",        // revision with no version
		"1.0-r",      // revision marker with no number
		"1.0_",       // suffix marker with no suffix
		"1.0_wat1",   // unknown suffix
		"latest",     // not a version at all
		"1.0-r1-r2",  // two revisions
		"1..0",       // empty component
	}
	var c APK
	for _, v := range bad {
		if _, err := c.Compare(v, "1.0-r0"); err == nil {
			t.Errorf("Compare(%q, \"1.0-r0\") = nil error, want ErrInvalid", v)
		}
		if _, err := c.Compare("1.0-r0", v); err == nil {
			t.Errorf("Compare(\"1.0-r0\", %q) = nil error, want ErrInvalid", v)
		}
	}
}

// The registry must hand out APK for release-qualified Alpine keys. A miss here
// means every Alpine package silently falls through to "no comparer".
func TestForAlpine(t *testing.T) {
	for _, eco := range []string{"Alpine:v3.19", "Alpine:v3.20", "Alpine:v3.2"} {
		c, ok := For(eco)
		if !ok {
			t.Errorf("For(%q) not found", eco)
			continue
		}
		if _, isAPK := c.(APK); !isAPK {
			t.Errorf("For(%q) = %T, want APK", eco, c)
		}
	}
	// Unversioned "Alpine" is not a key we ever build (D6) and must not resolve,
	// or a bug that drops the release would look like it worked.
	if _, ok := For("Alpine"); ok {
		t.Error(`For("Alpine") resolved; D6 requires the release in the key`)
	}
}
```

- [ ] **Step 2: Run it and watch it fail**

```bash
go test ./internal/version/ -run 'TestAPK|TestForAlpine' -v
```

Expected: compile failure — `undefined: APK`. That is the correct first failure.

- [ ] **Step 3: Implement the tokenizer**

`internal/version/apk.go`:

```go
package version

import (
	"fmt"
	"strings"
)

// APK orders Alpine package versions the way apk-tools does
// (apk-tools/src/version.c). It is deliberately a transliteration of that
// algorithm rather than an interpretation: the token-kind ordering and the
// leading-zero rule both produce results that look wrong until you check them
// against the source, and a "cleaner" rewrite is how false negatives get in.
type APK struct{}

// Token kinds in apk-tools' declaration order. The numeric order is
// load-bearing: when the two versions diverge in shape, the comparison falls
// back to comparing kinds, and a HIGHER kind means a LOWER version. apkEnd
// being near the top is what makes "1.0" sort below "1.0-r0".
type apkKind int

const (
	apkInitialDigit apkKind = iota
	apkDigit
	apkLetter
	apkSuffix
	apkSuffixNo
	apkCommitHash
	apkRevisionNo
	apkEnd
)

// Ascending suffix order, with the empty string — meaning "no suffix" — sitting
// in the middle at apkSuffixNone. Everything below it is a pre-release and
// everything above it is a post-release, so 1.0_rc1 < 1.0 < 1.0_p1.
var apkSuffixOrder = []string{
	"alpha", "beta", "pre", "rc",
	"", // apkSuffixNone
	"cvs", "svn", "git", "hg", "p",
}

const apkSuffixNone = 4

type apkPart struct {
	kind apkKind
	num  uint64 // digits, suffix numbers, revision
	str  string // raw text, for the string-sort path and letters/hashes
	sfx  int    // index into apkSuffixOrder, for apkSuffix
}

// parseAPK turns a version into its token stream. It rejects rather than
// guesses: an unparseable version must reach the caller as ErrInvalid so the
// package is reported as skipped (D9).
func parseAPK(v string) ([]apkPart, error) {
	if v == "" {
		return nil, fmt.Errorf("%w: empty version", ErrInvalid)
	}

	var parts []apkPart
	i := 0

	readNum := func() (uint64, string, bool) {
		start := i
		for i < len(v) && v[i] >= '0' && v[i] <= '9' {
			i++
		}
		if i == start {
			return 0, "", false
		}
		raw := v[start:i]
		var n uint64
		for _, c := range []byte(raw) {
			// Saturate instead of wrapping. A version number long enough to
			// overflow is not a real one, but wrapping would silently reorder it.
			if n > (1<<63)/10 {
				n = 1 << 63
				break
			}
			n = n*10 + uint64(c-'0')
		}
		return n, raw, true
	}

	n, raw, ok := readNum()
	if !ok {
		return nil, fmt.Errorf("%w: %q does not start with a digit", ErrInvalid, v)
	}
	parts = append(parts, apkPart{kind: apkInitialDigit, num: n, str: raw})

	for i < len(v) && v[i] == '.' {
		i++
		n, raw, ok := readNum()
		if !ok {
			return nil, fmt.Errorf("%w: %q has an empty component", ErrInvalid, v)
		}
		parts = append(parts, apkPart{kind: apkDigit, num: n, str: raw})
	}

	if i < len(v) && v[i] >= 'a' && v[i] <= 'z' {
		parts = append(parts, apkPart{kind: apkLetter, str: v[i : i+1]})
		i++
	}

	for i < len(v) && v[i] == '_' {
		i++
		start := i
		for i < len(v) && v[i] >= 'a' && v[i] <= 'z' {
			i++
		}
		name := v[start:i]
		sfx := -1
		for idx, s := range apkSuffixOrder {
			if s != "" && s == name {
				sfx = idx
				break
			}
		}
		if sfx < 0 {
			return nil, fmt.Errorf("%w: %q has unknown suffix %q", ErrInvalid, v, name)
		}
		parts = append(parts, apkPart{kind: apkSuffix, sfx: sfx, str: name})
		// The number is optional: "_git" with no digits is legal.
		if n, raw, ok := readNum(); ok {
			parts = append(parts, apkPart{kind: apkSuffixNo, num: n, str: raw})
		}
	}

	if i < len(v) && v[i] == '~' {
		i++
		start := i
		for i < len(v) && isHex(v[i]) {
			i++
		}
		if i == start {
			return nil, fmt.Errorf("%w: %q has an empty commit hash", ErrInvalid, v)
		}
		parts = append(parts, apkPart{kind: apkCommitHash, str: v[start:i]})
	}

	if i < len(v) && v[i] == '-' {
		i++
		if i >= len(v) || v[i] != 'r' {
			return nil, fmt.Errorf("%w: %q has a '-' that is not '-r'", ErrInvalid, v)
		}
		i++
		n, raw, ok := readNum()
		if !ok {
			return nil, fmt.Errorf("%w: %q has '-r' with no number", ErrInvalid, v)
		}
		parts = append(parts, apkPart{kind: apkRevisionNo, num: n, str: raw})
	}

	if i != len(v) {
		return nil, fmt.Errorf("%w: %q has trailing %q", ErrInvalid, v, v[i:])
	}
	return parts, nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}
```

- [ ] **Step 4: Implement the comparison**

Append to `internal/version/apk.go`:

```go
// Compare orders two apk versions. It reports an error rather than an ordering
// when either side is unparseable, because treating garbage as "not vulnerable"
// is a miss (D9).
func (APK) Compare(a, b string) (int, error) {
	pa, err := parseAPK(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseAPK(b)
	if err != nil {
		return 0, err
	}

	at := func(p []apkPart, i int) apkPart {
		if i < len(p) {
			return p[i]
		}
		return apkPart{kind: apkEnd}
	}

	for i := 0; ; i++ {
		ta, tb := at(pa, i), at(pb, i)

		if ta.kind != tb.kind {
			// A pre-release suffix loses to whatever the other side has,
			// including nothing at all: 1.0_rc1 < 1.0.
			if ta.kind == apkSuffix && ta.sfx < apkSuffixNone {
				return -1, nil
			}
			if tb.kind == apkSuffix && tb.sfx < apkSuffixNone {
				return 1, nil
			}
			// Otherwise the higher kind is the lower version. apkEnd is near
			// the top, so the stream that ran out first sorts below.
			if ta.kind > tb.kind {
				return -1, nil
			}
			return 1, nil
		}

		switch ta.kind {
		case apkEnd:
			return 0, nil

		case apkInitialDigit, apkDigit:
			// apk-tools: "if either of the digits have a leading zero, use raw
			// string comparison similar to Gentoo spec". So 1.01 < 1.1, which
			// numeric comparison would call equal.
			if strings.HasPrefix(ta.str, "0") || strings.HasPrefix(tb.str, "0") {
				if c := strings.Compare(ta.str, tb.str); c != 0 {
					return c, nil
				}
				continue
			}
			if c := cmpUint(ta.num, tb.num); c != 0 {
				return c, nil
			}

		case apkLetter, apkCommitHash:
			if c := strings.Compare(ta.str, tb.str); c != 0 {
				return c, nil
			}

		case apkSuffix:
			if c := cmpInt(ta.sfx, tb.sfx); c != 0 {
				return c, nil
			}

		case apkSuffixNo, apkRevisionNo:
			if c := cmpUint(ta.num, tb.num); c != 0 {
				return c, nil
			}
		}
	}
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
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

- [ ] **Step 5: Register APK for release-qualified Alpine keys**

`internal/version/version.go` already has `For(ecosystem string) (Comparer, bool)` over a
fixed `registry` map. Alpine keys carry a release (D6), so they cannot be map keys — the map
would need one entry per release forever. Extend `For` rather than adding a second lookup
function; two resolution paths are how they disagree later.

```go
func For(ecosystem string) (Comparer, bool) {
	// Distro ecosystems carry their release (D6), so "Alpine:v3.19" cannot be a
	// map key. The bare "Alpine" must NOT resolve: it is not a key we ever build,
	// and letting it through would make a bug that drops the release look like it
	// worked — every lookup landing in an empty bucket and reporting clean.
	if rel, ok := strings.CutPrefix(ecosystem, "Alpine:"); ok && rel != "" {
		return APK{}, true
	}
	c, ok := registry[ecosystem]
	return c, ok
}
```

- [ ] **Step 6: Run the tests**

```bash
go test ./internal/version/ -run 'TestAPK|TestForAlpine' -v
go test ./...
```

Expected: PASS, and no regression elsewhere.

- [ ] **Step 7: Verify against apk itself**

This is a comparator; a green self-written table proves less than it looks. Cross-check a
sample against the real implementation:

```bash
docker run --rm alpine:3.19 sh -c '
for p in "1.0 1.0-r0" "1.0_rc1 1.0" "1.0 1.0_p1" "1.01 1.1" "1.1.1k-r0 1.1.1l-r0"; do
  set -- $p
  apk version -t "$1" "$2" | sed "s|^|$1 vs $2 -> |"
done'
```

`apk version -t` prints `<`, `=`, or `>`. Every line must agree with the table. If Docker is
unavailable, say so in the report rather than skipping silently — an unverified comparator is
the single highest-risk artifact in this slice.

- [ ] **Step 8: Commit**

```bash
git add internal/version/apk.go internal/version/apk_test.go internal/version/version.go
git commit -m "feat: order apk versions the way apk-tools does"
```

---

## Task 2: Distro and the ecosystem key

**Files:**
- Create: `internal/pkgmeta/distro.go`
- Create: `internal/pkgmeta/distro_test.go`
- Modify: `internal/pkgmeta/package.go`

**Interfaces:**
- Consumes: `pkgmeta.Distro{ID, VersionID}` and `Target.Distro *Distro`, **both of which
  slice 1 already defined** in `package.go`. Do not redeclare them.
- Produces:
  - `func (d Distro) Ecosystem() (string, error)`
  - `var ErrNoEcosystem`
  - one new field, `Distro.PrettyName`, carried for reporting only

Move the existing `Distro` declaration out of `package.go` into the new `distro.go` so the
type and its method sit together; keep `Target.Distro` where it is.

### The derivation, and the case that must fail

syft reports `versionID = 3.19.9`; OSV's key is `Alpine:v3.19`. The key is
`"Alpine:v" + major + "." + minor`.

**Alpine edge has no OSV ecosystem.** `versionID` for an edge image is not a `X.Y` release,
and there is no `Alpine:edge` prefix in the bucket. Deriving a key anyway would produce a
lookup that always misses — every package silently clean. `Ecosystem()` must return an error
so the caller reports the packages as skipped with a count (D11: a result that cannot be
trusted is exit 2, not a clean verdict).

- [ ] **Step 1: Write the failing test**

`internal/pkgmeta/distro_test.go`:

```go
package pkgmeta

import (
	"strings"
	"testing"
)

func TestDistroEcosystem(t *testing.T) {
	tests := []struct {
		name   string
		distro Distro
		want   string
	}{
		{"syft reports a patch release", Distro{ID: "alpine", VersionID: "3.19.9"}, "Alpine:v3.19"},
		{"already major.minor", Distro{ID: "alpine", VersionID: "3.19"}, "Alpine:v3.19"},
		{"two-digit minor", Distro{ID: "alpine", VersionID: "3.20.1"}, "Alpine:v3.20"},
		{"oldest release in the bucket", Distro{ID: "alpine", VersionID: "3.2.0"}, "Alpine:v3.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.distro.Ecosystem()
			if err != nil {
				t.Fatalf("Ecosystem() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Ecosystem() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Each of these would otherwise produce a key that looks valid and matches
// nothing — every package silently clean. The error is the feature.
func TestDistroEcosystem_Unsupported(t *testing.T) {
	tests := []struct {
		name   string
		distro Distro
	}{
		{"edge has no OSV ecosystem", Distro{ID: "alpine", VersionID: "edge"}},
		{"edge as syft spells it", Distro{ID: "alpine", VersionID: "3.21_alpha20240807"}},
		{"no version at all", Distro{ID: "alpine", VersionID: ""}},
		{"major only", Distro{ID: "alpine", VersionID: "3"}},
		{"unsupported distro", Distro{ID: "debian", VersionID: "12"}},
		{"no id", Distro{ID: "", VersionID: "3.19"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.distro.Ecosystem()
			if err == nil {
				t.Fatalf("Ecosystem() = %q, nil error; want an error so the "+
					"packages are skipped rather than reported clean", got)
			}
			// The message reaches a human in the skip reason, so it has to name
			// what was wrong, not just that something was.
			if !strings.Contains(err.Error(), tt.distro.ID) &&
				!strings.Contains(err.Error(), "distro") {
				t.Errorf("error %q names neither the distro nor the problem", err)
			}
		})
	}
}
```

- [ ] **Step 2: Run it, watch it fail**

```bash
go test ./internal/pkgmeta/ -run TestDistroEcosystem -v
```

Expected: `undefined: Distro`.

- [ ] **Step 3: Implement**

`internal/pkgmeta/distro.go`:

```go
package pkgmeta

import (
	"errors"
	"fmt"
	"strings"
)

// ErrNoEcosystem means the target's distro has no ecosystem we can look up.
// Callers must surface the affected packages as skipped: a distro we cannot key
// is not a distro with no vulnerabilities.
var ErrNoEcosystem = errors.New("no vulnerability ecosystem for distro")

// Distro identifies the operating system of a Target. It belongs to the target,
// not to each package (D7): an image is Alpine 3.19; its packages are not.
// Fields mirror /etc/os-release, which is also what syft reports.
//
// Moved here from package.go, unchanged apart from PrettyName, so the type sits
// with the Ecosystem method that gives it meaning.
type Distro struct {
	ID         string // os-release ID, e.g. "alpine"
	VersionID  string // os-release VERSION_ID, e.g. "3.19.9"
	PrettyName string // os-release PRETTY_NAME; reporting only, never a lookup key
}

// Ecosystem returns the OSV ecosystem key for this distro — "Alpine:v3.19".
//
// The release is part of the key (D6) because the fixed version of a package
// differs per release. OSV publishes one ecosystem per Alpine minor release and
// nothing for edge, so anything that is not an X.Y release is an error rather
// than a best-effort key: a key nothing is stored under matches nothing, and a
// scan that matches nothing looks exactly like a clean one.
func (d Distro) Ecosystem() (string, error) {
	if d.ID == "" {
		return "", fmt.Errorf("%w: distro has no ID", ErrNoEcosystem)
	}
	if d.ID != "alpine" {
		return "", fmt.Errorf("%w: distro %q is not supported yet", ErrNoEcosystem, d.ID)
	}

	major, rest, ok := strings.Cut(d.VersionID, ".")
	if !ok {
		return "", fmt.Errorf("%w: distro %q version %q is not a X.Y release",
			ErrNoEcosystem, d.ID, d.VersionID)
	}
	minor, _, _ := strings.Cut(rest, ".")
	if !allDigits(major) || !allDigits(minor) {
		return "", fmt.Errorf("%w: distro %q version %q is not a X.Y release "+
			"(edge and pre-releases have no OSV ecosystem)",
			ErrNoEcosystem, d.ID, d.VersionID)
	}
	return "Alpine:v" + major + "." + minor, nil
}

func allDigits(s string) bool {
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
```

`internal/pkgmeta/package.go` — delete the `Distro` declaration that moved to `distro.go`.
`Target.Distro` is already there and stays exactly as it is:

```go
type Target struct {
	// Distro belongs to the target, not to each package (D7): an image is
	// Alpine 3.19, its packages are not. nil for language-only targets.
	Distro   *Distro
	Packages []Package
}
```

- [ ] **Step 4: Run the tests**

```bash
go test ./internal/pkgmeta/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pkgmeta/distro.go internal/pkgmeta/distro_test.go internal/pkgmeta/package.go
git commit -m "feat: derive the OSV ecosystem key from the target's distro"
```

---

## Task 3: Catalog apk packages from CycloneDX

**Files:**
- Modify: `internal/cataloger/cyclonedx/cyclonedx.go`
- Modify: `internal/cataloger/cyclonedx/cyclonedx_test.go`
- Create: `internal/cataloger/cyclonedx/testdata/alpine.cdx.json`

**Interfaces:**
- Consumes: `pkgmeta.Distro`, `pkgmeta.Target.Distro` (Task 2)
- Produces: `Parse` returns a `Target` whose `Distro` is set and whose apk packages carry
  `Ecosystem` and `Source`

### What to read, and what to do when it is absent

Three properties matter, all of them syft extensions rather than CycloneDX spec:

| Property | Lives on | Becomes |
|---|---|---|
| `syft:distro:id`, `syft:distro:versionID`, `syft:distro:prettyName` | the `"type": "operating-system"` component | `Target.Distro` |
| `syft:metadata:originPackage` | each apk component | `Package.Source` (D8) |
| `syft:location:0:layerID`, `syft:location:0:path` | each component | `Package.Locations` |

`Package.Ecosystem` for an apk component comes from `Target.Distro.Ecosystem()`, not from
the purl type — `purlTypeToEcosystem` deliberately has no `apk` entry, because the key needs
a release the package does not carry (D6).

**An SBOM with apk packages and no distro component is not an error and not empty.** It is a
target we cannot key. Catalog the packages with an empty `Ecosystem` so they are counted and
reported as skipped; do not drop them, and do not guess a release.

- [ ] **Step 1: Build the fixture**

Cut the real slice-1 SBOM down to something reviewable. Keep the `operating-system`
component, `libssl3` (source `openssl`, the D8 case), `busybox` (source is itself), and one
component with no `originPackage`.

```bash
python - <<'PY'
import json
src = "<path to the alpine SBOM>"
keep = {"libssl3", "busybox", "alpine-baselayout-data"}
d = json.load(open(src, encoding="utf-8"))
out = [c for c in d["components"]
       if c.get("type") == "operating-system" or c.get("name") in keep]
json.dump({"bomFormat": d["bomFormat"], "specVersion": d["specVersion"],
           "version": d["version"], "metadata": d["metadata"], "components": out},
          open("internal/cataloger/cyclonedx/testdata/alpine.cdx.json", "w",
               encoding="utf-8"), indent=1)
PY
```

Confirm the fixture is committed — `.gitignore` ignores `*.cdx.json` and un-ignores it only
under `**/testdata/**`:

```bash
git check-ignore -v internal/cataloger/cyclonedx/testdata/alpine.cdx.json || echo "not ignored - good"
```

- [ ] **Step 2: Write the failing tests**

Append to `internal/cataloger/cyclonedx/cyclonedx_test.go`:

```go
func TestParse_AlpineDistroAndSource(t *testing.T) {
	f, err := os.Open("testdata/alpine.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	target, _, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if target.Distro == nil {
		t.Fatal("Distro is nil; the operating-system component carries syft:distro:*")
	}
	if target.Distro.ID != "alpine" || target.Distro.VersionID != "3.19.9" {
		t.Errorf("Distro = %+v, want alpine/3.19.9", *target.Distro)
	}

	byName := map[string]pkgmeta.Package{}
	for _, p := range target.Packages {
		byName[p.Name] = p
	}

	// D8: the advisory is written against the source package. Without Source,
	// an openssl advisory is unreachable from libssl3 — a silent false negative.
	libssl, ok := byName["libssl3"]
	if !ok {
		t.Fatal("libssl3 not cataloged")
	}
	if libssl.Source == nil {
		t.Fatal("libssl3 has no Source; syft reports syft:metadata:originPackage")
	}
	if libssl.Source.Name != "openssl" {
		t.Errorf("libssl3 Source.Name = %q, want %q", libssl.Source.Name, "openssl")
	}
	if libssl.Ecosystem != "Alpine:v3.19" {
		t.Errorf("libssl3 Ecosystem = %q, want Alpine:v3.19 (D6 needs the release)",
			libssl.Ecosystem)
	}
	if len(libssl.Locations) == 0 || libssl.Locations[0].LayerDigest == "" {
		t.Error("libssl3 carries no layer provenance")
	}

	// The operating-system component describes the target; it is not a package
	// to scan, and counting it would inflate the component total.
	if _, ok := byName["alpine"]; ok {
		t.Error("the operating-system component was cataloged as a package")
	}
}

// An SBOM with apk packages but no distro cannot be keyed. The packages must
// still be cataloged so they are counted and reported as skipped — dropping
// them would shrink the denominator and make the scan look complete.
func TestParse_APKWithoutDistroIsKeptUnkeyed(t *testing.T) {
	const doc = `{
	  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
	  "components": [{
	    "type": "library", "name": "libssl3", "version": "3.1.4-r5",
	    "purl": "pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64"
	  }]
	}`
	target, cat, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cat.Components != 1 {
		t.Errorf("Components = %d, want 1", cat.Components)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1: an unkeyable package is still a package",
			len(target.Packages))
	}
	if eco := target.Packages[0].Ecosystem; eco != "" {
		t.Errorf("Ecosystem = %q, want empty: there is no distro to derive a release from", eco)
	}
}
```

- [ ] **Step 3: Run them, watch them fail**

```bash
go test ./internal/cataloger/cyclonedx/ -run 'TestParse_Alpine|TestParse_APK' -v
```

Expected: `Distro is nil`.

- [ ] **Step 4: Implement**

In `cyclonedx.go`, extend the component walk. Two passes are required, not one: the
`operating-system` component may appear after the packages that need its release, and the
real syft output puts it last (`components[16]` of 17).

```go
// syft emits the distro as a component of type "operating-system", carrying the
// os-release fields as properties. It is not a package to scan — it is what the
// packages are keyed by (D7) — so it is read in a first pass and excluded from
// the inventory in the second.
func distroFrom(components []component) *pkgmeta.Distro {
	for _, c := range components {
		if c.Type != "operating-system" {
			continue
		}
		var d pkgmeta.Distro
		for _, p := range c.Properties {
			switch p.Name {
			case "syft:distro:id":
				d.ID = p.Value
			case "syft:distro:versionID":
				d.VersionID = p.Value
			case "syft:distro:prettyName":
				d.PrettyName = p.Value
			}
		}
		// Fall back to the component's own fields: the properties are a syft
		// extension, but name/version are spec and carry the same thing.
		if d.ID == "" {
			d.ID = c.Name
		}
		if d.VersionID == "" {
			d.VersionID = c.Version
		}
		if d.ID == "" {
			return nil
		}
		return &d
	}
	return nil
}
```

In the package pass:

```go
// The ecosystem key for a distro package needs the release, which lives on the
// target rather than the package (D6, D7). Resolve it once.
var distroEcosystem string
if distro != nil {
	if eco, err := distro.Ecosystem(); err == nil {
		distroEcosystem = eco
	}
	// On error distroEcosystem stays empty and the packages are cataloged
	// unkeyed, so the matcher reports them as skipped with a reason. Guessing a
	// key here would turn "we cannot check this" into "this is clean".
}
```

and per component:

```go
if c.Type == "operating-system" {
	continue // described the target in the first pass; not an inventory item
}

// ... existing per-component handling ...

switch purl.Type {
case "apk":
	pkg.Ecosystem = distroEcosystem
	// syft reports the origin package name only. Alpine binary packages carry
	// their source package's version, so leaving Version empty is correct here
	// rather than a gap — the binary's own version is the one to compare.
	if origin := propValue(c, "syft:metadata:originPackage"); origin != "" {
		pkg.Source = &pkgmeta.SourcePackage{Name: origin}
	}
default:
	pkg.Ecosystem, _ = purlTypeToEcosystem(purl.Type)
}
```

- [ ] **Step 5: Run the tests**

```bash
go test ./internal/cataloger/cyclonedx/ -v
go test ./...
```

- [ ] **Step 6: Commit**

```bash
git add internal/cataloger/cyclonedx/ 
git commit -m "feat: catalog apk packages with their distro and source package"
```

---

## Task 4: Source-package indirect matching (D8)

**Do not delegate this task.** It is `Matcher` and `Evidence` — explainability is goal #1,
and the reasoning that makes a finding explainable is the thing being built.

**Files:**
- Modify: `internal/matcher/matcher.go`
- Modify: `internal/matcher/matcher_test.go`
- Modify: `internal/report/table.go`
- Modify: `internal/report/table_test.go`

**Interfaces:**
- Consumes: `Store.Lookup(ecosystem, name string)`, `pkgmeta.Package.Source`
- Produces: `Evidence.MatchedName` — the name that reached the advisory

### The shape of the lookup, and the bucket that turns out to be unnecessary

Alpine advisories are stored under the **source** package name: 32,069 of 33,589 affected
entries carry `?arch=source`, and the sampled `CVE-2013-4122` names `cyrus-sasl`. Slice 1's
`Put` already indexes advisories under `Affected[].Name`, so the source name is already a
lookup key. The matcher needs one more query, not a new index:

```
Lookup(eco, p.Name)                     // binary name — hits when they coincide
Lookup(eco, p.Source)  if Source != ""  // source name — the D8 case
```

**This contradicts the NOTE slice 1 left at `internal/matcher/matcher.go:57-66`**, which says
D8 will need three things: the matcher consulting `store.LookupBySource`, a cataloger
populating `p.Source`, and ingestion calling `store.PutSourceIndex`. Measurement says only
the middle one is real. OSV puts the source name in `Affected[].Name`, which `Put` already
indexes, so `PutSourceIndex` has nothing to add and `LookupBySource` has nothing to read.

**Rewrite that NOTE as part of this task.** A comment describing a design that measurement
disproved is worse than no comment — the next reader implements it.

`PutSourceIndex` / `LookupBySource` then have no production caller. `LookupBySource` is on
the `Store` interface, so removing it touches `store.go`, `bolt.go`, `bolt_test.go`, the
`by-source` bucket in `Create`, and `fakeStore` in `matcher_test.go`. Remove them, and say in
the commit message why: they were built speculatively in slice 1, the whole-branch review
found both revertible-green, and the shape they anticipated is not the shape the data has.
Debian is a deferred decision with its own recorded groundwork; re-adding a bucket then is
cheaper than a reader trusting an index nothing maintains.

If the implementer finds a caller this plan missed, that is a finding to raise — not a
reason to leave the dead API in silently.

Alpine binary packages share their source package's version (`libssl3 3.1.4-r5` comes from
`openssl 3.1.4-r5`), so the version comparison needs no adjustment. That is *why* indirect
matching works at all, and it belongs in a comment.

- [ ] **Step 1: Write the failing test**

```go
// D8: the advisory names the source package; the installed package is a binary
// one. Nine of the fifteen packages in alpine:3.19 have a source name that
// differs, including both libssl3 and libcrypto3 -> openssl. Losing this
// produces false NEGATIVES, which are silent.
func TestMatch_SourcePackageReachesTheAdvisory(t *testing.T) {
	adv := advWithRange("CVE-2024-openssl", "Alpine:v3.19", "openssl",
		"0", "3.1.4-r6", advisory.RangeEcosystem)
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Alpine:v3.19\x00openssl": {adv},
	}}

	p := pkg("libssl3", "3.1.4-r5", "Alpine:v3.19")
	p.Source = &pkgmeta.SourcePackage{Name: "openssl"}

	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1: an openssl advisory must reach libssl3 "+
			"through Package.Source; got %+v", len(res.Findings), res.Findings)
	}
	// Explainability (D10): "libssl3 is vulnerable" is not actionable without
	// naming the package the advisory was actually written against.
	if got := res.Findings[0].Evidence.MatchedName; got != "openssl" {
		t.Errorf("Evidence.MatchedName = %q, want %q", got, "openssl")
	}
}

// The same advisory must not be reported twice when the binary and source names
// both resolve to it.
func TestMatch_SourceAndBinaryNameDoNotDoubleReport(t *testing.T) {
	adv := advWithRange("CVE-2024-busybox", "Alpine:v3.19", "busybox",
		"0", "1.36.1-r16", advisory.RangeEcosystem)
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Alpine:v3.19\x00busybox": {adv},
	}}

	p := pkg("busybox", "1.36.1-r15", "Alpine:v3.19")
	// syft reports originPackage even when it equals the package's own name.
	p.Source = &pkgmeta.SourcePackage{Name: "busybox"}

	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("Findings = %d, want 1: one advisory reached through two names "+
			"is still one finding", len(res.Findings))
	}
}

// A package we cannot key is reported as skipped with a reason, never folded
// into a clean verdict (D11).
func TestMatch_UnkeyablePackageIsSkippedNotClean(t *testing.T) {
	p := pkg("libssl3", "3.1.4-r5", "") // no ecosystem: distro had no OSV key
	res, err := New(fakeStore{}).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d, want 1", len(res.Skipped))
	}
	if res.Skipped[0].Reason == "" {
		t.Error("skip carries no reason; the count alone tells nobody what to fix")
	}
}
```

- [ ] **Step 2: Run, watch it fail**

```bash
go test ./internal/matcher/ -run 'TestMatch_Source|TestMatch_Unkeyable' -v
```

- [ ] **Step 3: Add `MatchedName` to `Evidence`**

```go
type Evidence struct {
	// ... existing fields ...

	// MatchedName is the package name that reached the advisory. It differs from
	// the package's own name when the advisory was written against the source
	// package (D8) — an openssl advisory matching libssl3. Without it the report
	// says a package is vulnerable and gives no way to check the claim.
	MatchedName string
}
```

- [ ] **Step 4: Query both names**

```go
// Distro advisories are written against source packages while what is installed
// are binary packages (D8), so the source name is a second lookup key. Both
// names are queried because they coincide for most packages and diverge for the
// ones that matter: alpine:3.19 has nine of fifteen diverging, including
// libssl3 and libcrypto3 both sourced from openssl.
//
// The version needs no adjustment: an Alpine binary package carries its source
// package's version, which is what makes indirect matching sound.
names := []string{p.Name}
if p.Source != nil && p.Source.Name != "" && p.Source.Name != p.Name {
	names = append(names, p.Source.Name)
}
```

Run the existing per-package `seen` / `reported` dedup across both names so one advisory
reached through two names stays one finding.

The `Affected` filter must accept either name — mirror the store's key equality for each,
normalizing both sides exactly as the store does.

- [ ] **Step 5: Delete the dead by-source API and correct the NOTE**

Remove, in this order so the build tells you if a caller was missed:

1. `LookupBySource` from the `Store` interface in `internal/store/store.go`
2. `Bolt.LookupBySource` and `Bolt.PutSourceIndex` in `internal/store/bolt.go`
3. `bucketBySource` from `Create` and from the bucket list
4. `TestLookupBySource` and the `PutSourceIndex` calls in `internal/store/bolt_test.go`
5. `fakeStore.LookupBySource` in `internal/matcher/matcher_test.go`

Then rewrite the D8 NOTE at `internal/matcher/matcher.go:57-66`. It currently prescribes
`LookupBySource` + `PutSourceIndex`; replace it with what the data showed:

```go
// D8: distro advisories are written against source packages while installed
// packages are binary packages, so p.Source is a second lookup key. OSV puts
// the source name directly in Affected[].Name — 32,069 of 33,589 Alpine
// affected entries carry ?arch=source — which the ordinary advisory index
// already covers, so no separate by-source index is needed. Slice 1 reserved
// one on the assumption it would be; measuring the data retired it.
```

- [ ] **Step 5b: Confirm the deletion is real**

```bash
grep -rn "LookupBySource\|PutSourceIndex\|bucketBySource" --include='*.go' . && \
  echo "FAIL: references remain" || echo "clean"
go build ./... && go test ./...
```

- [ ] **Step 6: Show the source package in the report**

Where `MatchedName` differs from the package name, the table must say so — otherwise the
finding is unexplainable. Add it to the existing PACKAGE column rather than a new column:

```
PACKAGE            INSTALLED    FIXED IN     VULNERABILITY   SEVERITY  ALIASES
libssl3 (openssl)  3.1.4-r5     3.1.4-r6     CVE-2024-…      high      …
```

- [ ] **Step 7: Run everything**

```bash
go test ./...
```

- [ ] **Step 8: Commit**

```bash
git add internal/matcher/ internal/report/ internal/store/
git commit -m "feat: reach source-package advisories from binary packages (D8)"
```

---

## Task 5: Ingest Alpine advisories

**Files:**
- Create: `internal/provider/osv/alpine.go`
- Create: `internal/provider/osv/alpine_test.go`
- Modify: `internal/provider/osv/fetch.go`
- Modify: `internal/dbcmd/dbcmd.go`

**Interfaces:**
- Consumes: the existing `Convert(data []byte, wantEcosystem string)` and `Fetch`
- Produces: `func AlpineEcosystems(ctx context.Context, c *http.Client) ([]string, error)`

### Why discovery rather than a hardcoded list

`ecosystems.txt` lists `Alpine` and no versioned keys — all 52 entries are colon-free — so
the release list has to come from somewhere else. The bucket's JSON listing has it:

```
https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o?delimiter=/&prefix=Alpine
→ {"prefixes": ["Alpine/", "Alpine:v3.10/", …, "Alpine:v3.20/"]}
```

A hardcoded list is simpler and ages badly in the worst direction: Alpine releases every six
months, and a missing release is not an error but a scan that finds nothing. Discovery keeps
`db update` correct without a release.

Drop the unversioned `Alpine/` prefix — an advisory keyed without a release cannot be matched
against a release-qualified package (D6).

**Fetch every release you claim to support.** `Alpine:v3.19/all.zip` is missing 71 of the
2,242 `Alpine:v3.16` entries, so one release's archive is not a usable substitute for
another's.

- [ ] **Step 1: Write the failing test**

```go
// The bucket listing is the only place the versioned keys appear:
// ecosystems.txt has none (52 entries, zero colons).
func TestAlpineEcosystems(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"prefixes":["Alpine/","Alpine:v3.19/","Alpine:v3.2/","Alpine:v3.20/"]}`)
	}))
	defer srv.Close()

	got, err := alpineEcosystemsFrom(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("alpineEcosystemsFrom: %v", err)
	}
	want := []string{"Alpine:v3.2", "Alpine:v3.19", "Alpine:v3.20"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// An unversioned key cannot match a release-qualified package (D6). Ingesting it
// would put records under a key no lookup ever uses — invisible dead weight.
func TestAlpineEcosystems_DropsUnversioned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"prefixes":["Alpine/"]}`)
	}))
	defer srv.Close()

	got, err := alpineEcosystemsFrom(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("alpineEcosystemsFrom: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

// A listing we cannot read must fail loudly. Returning an empty list would build
// a database with no Alpine data and report success.
func TestAlpineEcosystems_EmptyListingIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	if _, err := alpineEcosystemsFrom(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Error("empty listing returned nil error; a silent empty database is worse than a failure")
	}
}
```

- [ ] **Step 2: Run, watch it fail**

```bash
go test ./internal/provider/osv/ -run TestAlpineEcosystems -v
```

- [ ] **Step 3: Implement discovery**

`internal/provider/osv/alpine.go`:

```go
package osv

// Alpine ecosystems are release-qualified (D6) and the published
// ecosystems.txt does not list them — it carries the bare "Alpine" and no
// versioned key at all. The bucket's JSON listing is where they appear, so
// db update discovers them rather than carrying a hardcoded list that would
// silently stop covering releases published after this build.
const alpineListingURL = "https://storage.googleapis.com/storage/v1/b/" +
	"osv-vulnerabilities/o?delimiter=/&prefix=Alpine&fields=prefixes"

func AlpineEcosystems(ctx context.Context, c *http.Client) ([]string, error) {
	return alpineEcosystemsFrom(ctx, c, alpineListingURL)
}

func alpineEcosystemsFrom(ctx context.Context, c *http.Client, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list Alpine ecosystems: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list Alpine ecosystems: %s", resp.Status)
	}

	var listing struct {
		Prefixes []string `json:"prefixes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		return nil, fmt.Errorf("decode Alpine ecosystem listing: %w", err)
	}

	var out []string
	for _, p := range listing.Prefixes {
		eco := strings.TrimSuffix(p, "/")
		// The bare "Alpine" prefix has no release. An advisory stored under it
		// could never match a release-qualified package (D6), so ingesting it
		// would add records no lookup ever reaches.
		if _, rel, ok := strings.Cut(eco, ":"); !ok || rel == "" {
			continue
		}
		out = append(out, eco)
	}
	// An empty result means the listing shape changed or the bucket moved.
	// Returning it would build a database with no Alpine data and call it a
	// success — the failure mode this whole slice exists to prevent.
	if len(out) == 0 {
		return nil, fmt.Errorf("Alpine ecosystem listing yielded no releases: %s", url)
	}

	// Sort by release, not lexically: "Alpine:v3.2" sorts ABOVE "Alpine:v3.19"
	// as a string, and db status would print a list that looks corrupted.
	slices.SortFunc(out, func(a, b string) int {
		return cmpRelease(a, b)
	})
	return out, nil
}

// cmpRelease orders "Alpine:vX.Y" by X then Y. Anything unparseable sorts last
// rather than panicking: a new key shape should be visible, not fatal.
func cmpRelease(a, b string) int {
	amaj, amin, aok := releaseParts(a)
	bmaj, bmin, bok := releaseParts(b)
	switch {
	case !aok && !bok:
		return strings.Compare(a, b)
	case !aok:
		return 1
	case !bok:
		return -1
	}
	if amaj != bmaj {
		return cmp.Compare(amaj, bmaj)
	}
	return cmp.Compare(amin, bmin)
}

func releaseParts(eco string) (major, minor int, ok bool) {
	_, rel, found := strings.Cut(eco, ":v")
	if !found {
		return 0, 0, false
	}
	majStr, minStr, found := strings.Cut(rel, ".")
	if !found {
		return 0, 0, false
	}
	major, err := strconv.Atoi(majStr)
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(minStr)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}
```

- [ ] **Step 4: Wire into `db update`**

`osv.New(ecosystems, baseURL)` already takes the list, and `Fetch` already loops over it
building `%s/%s/all.zip` — the Alpine archives have the same shape, so nothing in `Fetch`
changes. Only the list does.

Discovery is a network call, so it belongs on the `db update` path with the rest of them,
resolved before the provider is constructed:

```go
// Ecosystems is the language-ecosystem scope. It is a fixed list because these
// keys never change. Distro ecosystems cannot be: they carry a release (D6) and
// Alpine publishes a new one every six months, so a hardcoded list would not
// fail — it would quietly stop covering new images.
var Ecosystems = []string{"Go", "npm", "PyPI"}

// AllEcosystems is what `assay db update` fetches: the fixed language list plus
// whatever Alpine releases the bucket currently publishes.
func AllEcosystems(ctx context.Context) ([]string, error) {
	c := &http.Client{Timeout: 2 * time.Minute}
	alpine, err := AlpineEcosystems(ctx, c)
	if err != nil {
		// Do not fall back to the language list. Building a database that
		// silently contains no Alpine data, then scanning an Alpine image
		// against it, reports "no known vulnerabilities" — the exact failure
		// exit code 2 exists to prevent (D11).
		return nil, err
	}
	return append(slices.Clone(Ecosystems), alpine...), nil
}
```

At the `db update` call site, resolve the list and surface a failure as exit 2 with the same
wording as the other provider failures:

```go
ecosystems, err := osv.AllEcosystems(ctx)
if err != nil {
	fmt.Fprintf(stderr, "error: resolve ecosystems: %v\n", err)
	return 2
}
providers := []Provider{osv.New(ecosystems, "")}
```

Two properties the existing code already gives us, worth asserting rather than assuming:

- Withdrawn records are dropped at ingestion (D16). v3.19 has 18.
- A record whose `affected[]` spans several releases keeps every entry (the slice-1 fix), so
  ingesting `Alpine:v3.19` also indexes that record's `Alpine:v3.16` entries. That is extra
  coverage, not a bug — and it is *not* a substitute for fetching v3.16, which has 71 entries
  v3.19's archive never mentions.

- [ ] **Step 5: Report per-release counts in `db status`**

`db status` currently prints one row per provider. Alpine adds ~19 ecosystems; print the
Alpine rows collapsed into one with a release count, so the table stays readable:

```
PROVIDER  DATA AS OF  RECORDS  SOURCE
osv       2026-07-29  27702    https://osv-vulnerabilities.storage.googleapis.com
osv       2026-07-30  15184    Alpine, 19 releases
```

- [ ] **Step 6: Run everything**

```bash
go test ./...
```

- [ ] **Step 7: Commit**

```bash
git add internal/provider/osv/ internal/dbcmd/
git commit -m "feat: discover and ingest Alpine's release-qualified ecosystems"
```

---

## Task 6: End-to-end and the grype differential

**Files:**
- Modify: `README.md`, `README.ko.md` (both in this commit — English is canonical)
- Modify: `docs/deferred-decisions.md`, `docs/deferred-decisions.ko.md`

- [ ] **Step 1: Build a real database**

```bash
export ASSAY_DB_DIR=$(mktemp -d)
go run ./cmd/assay db update
go run ./cmd/assay db status
```

Record the actual on-disk size and record count. **Do not carry the estimate into the
README** — slice 1 shipped with an 86 MB / 28,613 estimate against a measured 64 MB / 27,702.

- [ ] **Step 2: Scan the alpine SBOM**

```bash
go run ./cmd/assay scan alpine.cdx.json; echo "exit=$?"
```

The slice-1 baseline is `17 component(s) seen, 0 evaluated, 0 finding(s), 17 not evaluated`
and exit 2. Expected now: 16 packages evaluated (the 17th component is the
`operating-system` entry, which describes the target and is not a package), findings > 0,
exit 0.

- [ ] **Step 3: Differential against grype**

```bash
grype sbom:alpine.cdx.json -o json > grype.json
go run ./cmd/assay scan alpine.cdx.json > assay.txt
```

Compare the **CVE sets**, not the counts — equal counts with different contents is the
failure this check exists to catch. Report misses and extras separately: a miss is a silent
false negative and is the serious direction.

Divergence is expected to be larger than slice 1's zero. grype's Alpine data comes from
Alpine's own secdb, ours from OSV, and the two genuinely differ. Investigate each miss; a
miss traced to a data-source difference is a finding to record, not a bug to fix.

- [ ] **Step 4: Mutation-test the slice's own fixes**

Each of these must turn the suite red. A green mutation means the fix is undefended, which
is what the slice-1 review round existed to catch.

| Mutation | Must fail |
|---|---|
| `Distro.Ecosystem` returns `"Alpine:v" + VersionID` untruncated | Task 2 tests |
| `Distro.Ecosystem` returns a key for edge instead of an error | Task 2 tests |
| matcher queries `p.Name` only, not `p.Source` | Task 4 tests |
| cataloger drops apk components with no distro | Task 3 tests |
| apk suffix table puts `p` below `""` | Task 1 tests |
| apk digit comparison ignores the leading-zero rule | Task 1 tests |
| `version.For` resolves bare `"Alpine"` | Task 1 tests |

Run them one at a time, reverting between. A mutation that fails to **compile** has not been
tested — the compiler caught it, not the suite. Keep the symbol alive and re-run.

- [ ] **Step 5: Update the docs**

README, both languages, same commit:

- Roadmap: slice ② splits into 2a (done) and 2b (next). Tick 2a's items.
- Status: `assay scan` now handles Alpine SBOMs; images still are not read directly.
- The database section: real measured size and record count.
- The grype differential table gains the alpine row, with the honest divergence.

`docs/deferred-decisions.md` already carries slice 2b under **"Next work — committed, not
deferred"**, written when this plan was. Do not re-add it. Update it only if 2a changed
something it asserts — for example if the fetcher boundary turned out not to sit where that
entry says it does.

- [ ] **Step 6: Commit**

```bash
git add README.md README.ko.md docs/deferred-decisions.md docs/deferred-decisions.ko.md
git commit -m "docs: record slice 2a's results and name 2b as the next work"
```

---

## Done when

- `assay scan alpine.cdx.json` reports Alpine findings and exits 0
- An `openssl` advisory reaches `libssl3` **and** `libcrypto3`, with `Evidence.MatchedName`
  naming `openssl` in the report
- An Alpine edge SBOM reports its packages as skipped with a reason and exits 2 — never a
  clean verdict
- The apk comparer's table agrees with `apk version -t` on every cross-checked pair
- Every mutation in Task 6 Step 4 turns the suite red
- The grype differential is run, and each divergence is either explained or recorded
- README and deferred-decisions are updated in both languages, in the same commit

## Not in this slice

Reading images (layers, whiteouts, `/lib/apk/db/installed`, `/etc/os-release` from a real
filesystem), any fetcher, Debian, RHEL, `--fail-on`, and JSON output. Slice 2b is the next
work item; the rest keep their existing entries in `docs/deferred-decisions.md`.
