# Slice 2b — Reading Container Images Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** `assay scan alpine:3.19` produces the same findings as
`syft … | assay scan -`, with no syft in the loop.

**Architecture:** `go-containerregistry` supplies an image — from a registry, a
`docker save` tarball, or an OCI layout directory — as an ordered list of layers plus a
config (D19). Everything after that is ours: walk the layers newest-first, honour whiteouts,
read `/etc/os-release` and `/lib/apk/db/installed`, and hand slice 2a the `Target` it already
knows how to match.

**Tech Stack:** Go 1.26, `go.etcd.io/bbolt`, and `github.com/google/go-containerregistry`.
`CGO_ENABLED=0`.

---

## What 2a already provides

Slice 2a matches Alpine packages given a `pkgmeta.Target`. This slice only has to build one
without syft. Nothing in the matcher, store, comparer, or report changes.

| Already working | Where |
|---|---|
| `Target.Distro` → `Alpine:vX.Y` | `pkgmeta.Distro.Ecosystem()` |
| apk version ordering | `version.APK` |
| Source-package indirect matching (D8) | `matcher.Match` queries `p.Source.Name` too |
| Alpine advisory ingestion | `osv.Ecosystems` includes `Alpine` |
| Report, exit codes, skip counting | `report.Table`, `scancmd` |

**The bar is a differential against 2a itself.** `assay scan alpine:3.19` must produce the
same finding set as `assay scan alpine.cdx.json` on a syft SBOM of the same image. That is a
stronger oracle than grype, because any divergence is ours alone — the database, matcher, and
comparer are held fixed.

---

## Measured inputs

Measured 2026-07-31 against live registries and a real `alpine:3.19` layer. Do not
re-derive; do not replace with estimates.

**Registry protocol**

| Registry | Unauthenticated manifest request | Token source | Token size |
|---|---|---|---|
| Docker Hub | `401` + `WWW-Authenticate: Bearer realm=…,service=…,scope=…` | `auth.docker.io/token` | 2,658 chars |
| GHCR | `401` + challenge naming its own host | `ghcr.io/token` | 52 chars |
| Quay | **`200`** — no challenge at all | n/a | n/a |

`alpine:3.19` on Docker Hub is an OCI index with **14 manifests**, several of them
`platform.os == "unknown"` / `architecture == "unknown"` — attestation manifests that must be
skipped when selecting a platform. The `linux/amd64` manifest has **one** layer, 3.26 MB
gzipped, and a config of 581 bytes.

**Layer digests are not diff IDs.** The manifest's layer digest is
`sha256:17a39c0ba978…` (compressed); the config's `rootfs.diff_ids[0]` is
`sha256:0b44b2151d78…` (uncompressed). syft reports the **diff ID** as
`syft:location:0:layerID`, and the 2a fixture carries exactly `sha256:0b44b2151d78…`.
`Location.LayerDigest` must therefore be the diff ID, or every cross-tool comparison and
every layer attribution silently points at the wrong blob.

**`/etc/os-release`** in that layer, verbatim:

```
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.19.9
PRETTY_NAME="Alpine Linux v3.19"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"
```

Values are shell-quoted: some bare, some double-quoted. `VERSION_ID=3.19.9` is what
`Distro.Ecosystem()` truncates to `Alpine:v3.19` — 2a already handles that.

**`/lib/apk/db/installed`** — 15 records for this image, matching syft's 15 packages.
Records are separated by a blank line; every line is `<letter>:<value>`. Field counts across
the whole file:

| Field | Count | Meaning |
|---|---:|---|
| `P` | 15 | package name |
| `V` | 15 | version |
| `A` | 15 | architecture |
| `o` | 15 | **origin — the source package (D8)** |
| `C` `I` `L` `S` `T` `U` `c` `m` `t` | 15 each | checksum, size, licence, description, url, maintainer, build time |
| `F` | 145 | directory entry |
| `R` | 111 | file entry |
| `Z` | 111 | file checksum |
| `a` | 57 | file owner/permissions |
| `M` | 5 | directory owner/permissions |
| `D` | 11 | dependencies |

A first record, trimmed to the fields that matter:

```
P:alpine-baselayout
V:3.4.3-r2
A:x86_64
o:alpine-baselayout
```

**Keys are case-sensitive and the cases collide in meaning.** `A:` is the package
architecture; `a:` is a *file's* owner/permission triple, and there are 57 of them. `T:` is
the description; `t:` is the build timestamp. A parser that upper-cases or lower-cases keys
before dispatching will read file permissions as an architecture. The file-level fields
outnumber the package-level ones roughly 5:1, so this is the common case, not the edge.

**Whiteouts** (OCI image-spec, `layer.md`):

- A deleted path is marked by a sibling entry named `.wh.` + the basename. `a/.wh.file2`
  deletes `a/file2`.
- `.wh..wh..opq` inside a directory deletes **all** of that directory's children in lower
  layers, recursively.
- Whiteouts apply only to lower layers, and the whiteout entry itself must not appear in the
  result.

**Docker Hub rate-limits anonymous pulls, and it will bite during this slice.** A live
pull of `alpine:3.19` returned `TOOMANYREQUESTS: You have reached your unauthenticated pull
rate limit` partway through development — the same limit slice 1 hit. Use
`mirror.gcr.io/library/alpine:3.19` for every live check and for the end-to-end. It serves
the identical image (diff ID `sha256:0b44b2151d78…`, one layer, 526 entries) and requires no
token. Do not paper over the limit with retries: it is measured in hours, not seconds.

**Dependency cost** (D19), measured by linking each combination:

| Imports | Linked modules | Packages | Binary |
|---|---:|---:|---|
| stdlib only (hand-written pull) | 0 | 0 | 6.3 MB |
| `remote` | 9 | 45 | 7.0 MB |
| `remote` + `tarball` + `layout` | 9 | 46 | 6.8 MB |
| … + `daemon` | **27** | **114** | 7.7 MB |

The daemon source is excluded on that evidence. An image already present locally reaches us
through `docker save`, which the tarball source reads.

---

## Global Constraints

- Go 1.26. Dependencies: `go.etcd.io/bbolt` and `github.com/google/go-containerregistry`
  (D19). A third is a decision to raise, not to make inside a task.
- `CGO_ENABLED=0`. `make test` fails without a C toolchain; use `go test ./...`.
- **Do not import `pkg/v1/daemon`.** It triples the linked module count (D19).
- **D14 was narrowed for this slice** and now reads "a scan never fetches vulnerability
  data". Only the target may be fetched, and only when the user names a remote one. A scan
  of an SBOM, a `docker-archive:` tarball, or an `oci-dir:` layout must make **no network
  call at all** — that is the air-gapped path and a test must hold it there.
- **Layer contents are never written to disk.** Stream each layer and read the wanted
  entries in passing (D19).
- **`Location.LayerDigest` carries the diff ID**, not the manifest layer digest.
- **D6/D7/D8** unchanged: release-qualified ecosystem keys, distro on `Target`,
  `Package.Source` populated from apk's `o:` field.
- **D11**: a target we cannot read exits 2. A scan that evaluates nothing is never clean.
- Comments explain *why*. Match the register in `matcher.go` and `apk.go`.
- Docs are bilingual (English canonical, same commit). Plans are exempt — this file is
  English only.

---

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `internal/source/source.go` | `Source` interface; `Layer`, `Image` types |
| `internal/source/image.go` | go-containerregistry → `Image`, for all three references |
| `internal/source/image_test.go` | reference parsing and source selection |
| `internal/source/walk.go` | layer walk, newest-first, whiteout-aware |
| `internal/source/walk_test.go` | whiteout semantics against synthetic layers |
| `internal/cataloger/osrelease/osrelease.go` | `/etc/os-release` → `pkgmeta.Distro` |
| `internal/cataloger/osrelease/osrelease_test.go` | quoting, absent fields, junk |
| `internal/cataloger/apkdb/apkdb.go` | `/lib/apk/db/installed` → `[]pkgmeta.Package` |
| `internal/cataloger/apkdb/apkdb_test.go` | field cases, record boundaries, `o:` |
| `internal/cataloger/apkdb/testdata/installed` | the real 15-record file |

**Modified**

| File | Change |
|---|---|
| `internal/scancmd/scancmd.go` | dispatch on target kind: SBOM path vs image reference |
| `cmd/assay/main.go` | usage text |
| `go.mod`, `go.sum` | the D19 dependency |

---

## Task 1: The `Source` boundary and image loading

**Files:**
- Create: `internal/source/source.go`, `internal/source/image.go`, `internal/source/image_test.go`
- Modify: `go.mod`

**Interfaces:**
- Produces:
  - `type Layer struct { DiffID string; Open func() (io.ReadCloser, error) }`
  - `type Image struct { Layers []Layer }` — ordered base-first, as the config lists them
  - `func Open(ctx context.Context, ref string) (*Image, error)`

### Reference forms and how they are told apart

| User writes | Source | Network |
|---|---|---|
| `alpine:3.19`, `ghcr.io/o/r@sha256:…` | registry | yes |
| `docker-archive:path.tar` | `pkg/v1/tarball` | no |
| `oci-dir:path/` | `pkg/v1/layout` | no |

An unprefixed argument that names an existing file is an SBOM, not an image — that is how
2a's behaviour is preserved. Decide by explicit prefix first, then by whether the path
exists, and only then treat it as a registry reference. Guessing in the other order makes
`assay scan ./alpine.tar` try to pull a repository named `alpine.tar`, and the error a user
sees is about registries rather than about their file.

- [ ] **Step 1: Write the failing test**

```go
package source

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		ref  string
		want kind
	}{
		{"docker-archive:image.tar", kindTarball},
		{"oci-dir:./layout", kindLayout},
		{"alpine:3.19", kindRegistry},
		{"ghcr.io/owner/repo@sha256:" + strings.Repeat("a", 64), kindRegistry},
		{"registry.example.com:5000/team/app:v1", kindRegistry},
	}
	for _, tt := range tests {
		if got := classify(tt.ref); got != tt.want {
			t.Errorf("classify(%q) = %v, want %v", tt.ref, got, tt.want)
		}
	}
}

// A host:port registry reference and a docker-archive prefix both contain a
// colon. Splitting on the first colon without checking the scheme set would
// route registry.example.com:5000/... to the tarball loader.
func TestClassify_HostPortIsNotAScheme(t *testing.T) {
	if got := classify("registry.example.com:5000/team/app:v1"); got != kindRegistry {
		t.Errorf("classify = %v, want kindRegistry", got)
	}
}
```

- [ ] **Step 2: Run it, watch it fail**

```bash
go test ./internal/source/ -run TestClassify -v
```

Expected: `undefined: classify`.

- [ ] **Step 3: Add the dependency**

```bash
go get github.com/google/go-containerregistry@latest
go mod tidy
```

Then confirm the daemon package did not come in — it is the one import that triples the
tree (D19):

```bash
go list -deps ./... | grep -c 'go-containerregistry/pkg/v1/daemon' # must print 0
go list -deps ./... | grep -c '^github.com\|^golang.org\|^gopkg.in' # record the number
```

- [ ] **Step 4: Implement**

`internal/source/source.go`:

```go
// Package source turns a scan target into the layers and metadata a cataloger
// needs. It is the only place that knows a target can be a registry reference,
// a tarball, or a directory; everything downstream sees the same Image.
package source

import "io"

// Layer is one filesystem layer, identified by its DIFF ID — the digest of the
// uncompressed tar, which is what the image config lists in rootfs.diff_ids.
//
// This is deliberately not the manifest's layer digest, which covers the
// COMPRESSED blob and is a different value: sha256:17a39c0ba978… against
// sha256:0b44b2151d78… for the same alpine:3.19 layer. syft and grype report
// the diff ID, so using the other one would make every cross-tool comparison
// and every "which layer introduced this" answer quietly wrong.
type Layer struct {
	DiffID string
	Open   func() (io.ReadCloser, error)
}

// Image is layers in the order the config lists them: base first. Callers that
// resolve file contents must walk it in reverse, because a later layer wins.
type Image struct {
	Layers []Layer
}
```

`internal/source/image.go` — `classify` plus `Open`. Registry references go through
`name.ParseReference` and `remote.Image`; tarballs through `tarball.ImageFromPath`; layouts
through `layout.ImageIndexFromPath`. Take the layer list from `img.Layers()` and the diff ID
from each layer's `DiffID()`, not from the manifest.

For a multi-platform index, select `linux` and the host architecture, and **skip manifests
whose platform is `unknown/unknown`** — `alpine:3.19` carries several of those attestation
entries among its 14. If no manifest matches, fail with the platforms that were on offer;
a scan of the wrong architecture's image is a wrong answer that looks like a right one.

- [ ] **Step 5: Run the tests**

```bash
go test ./internal/source/ -v
go test ./...
```

- [ ] **Step 6: Commit**

```bash
git add internal/source/ go.mod go.sum
git commit -m "feat: load container images from a registry, tarball, or OCI layout"
```

---

## Task 2: Layer walk with whiteouts

**Do not delegate this task.** Whiteout handling decides which files exist, and getting it
wrong removes packages from the inventory — a false negative that looks like a small image.

**Files:**
- Create: `internal/source/walk.go`, `internal/source/walk_test.go`

**Interfaces:**
- Consumes: `Image`, `Layer` (Task 1)
- Produces: `func (img *Image) Files(want []string) (map[string]FileFromLayer, error)`
  where `FileFromLayer` carries the bytes and the diff ID of the layer they came from

### The rule, and why the direction matters

Walk **newest layer first** and take the first hit for each wanted path. A path is resolved
once; later (lower) layers cannot overwrite it.

Whiteouts must be honoured while walking, or a package uninstalled in a later layer stays in
the inventory forever:

- an entry named `.wh.<base>` in directory `d` means `d/<base>` is deleted in all lower
  layers;
- an entry named `.wh..wh..opq` in directory `d` means every child of `d` is deleted in all
  lower layers, recursively;
- whiteout entries are instructions, never results — they must not appear in the output.

**Do not extract to disk.** Stream each layer's tar and copy out only the wanted entries.
Path traversal, symlink escape, and archive bombs are extraction vulnerabilities; not
extracting removes the class rather than defending against it.

- [ ] **Step 1: Write the failing tests**

```go
// A file present in the base layer and absent from the top must still be found:
// nothing deleted it.
func TestFiles_TakesTheNewestLayerThatHasIt(t *testing.T) { /* two layers, both carry
   etc/os-release with different bytes; expect the upper layer's bytes and its diff ID */ }

// The whiteout marker deletes the lower layer's copy. Without this a package
// removed by `apk del` in a later layer is still reported as installed.
func TestFiles_WhiteoutHidesLowerLayer(t *testing.T) { /* lower: lib/apk/db/installed;
   upper: lib/apk/db/.wh.installed; expect not found */ }

// The opaque marker deletes every child, not just the ones named.
func TestFiles_OpaqueWhiteoutHidesEveryChild(t *testing.T) { /* lower: a/one, a/two;
   upper: a/.wh..wh..opq; expect neither found */ }

// A whiteout is an instruction. Returning it as a file would hand the apk
// parser the literal bytes of a marker.
func TestFiles_WhiteoutEntriesAreNeverReturned(t *testing.T) { /* want ".wh.installed";
   expect not found even though the entry exists */ }

// Whiteouts apply downward only. One in the base layer must not hide a file
// added above it.
func TestFiles_WhiteoutDoesNotApplyUpward(t *testing.T) { /* lower: .wh.x; upper: x;
   expect x found */ }
```

Build the fixtures with `archive/tar` in memory — a helper taking
`map[string][]byte` per layer keeps each test to its subject.

- [ ] **Step 2: Run, watch them fail**

- [ ] **Step 3: Implement the walk**

Iterate `img.Layers` from `len-1` down to `0`. Per layer, scan the tar once, recording
whiteouts and matching wanted paths. Apply a layer's whiteouts only to layers **below** it,
and resolve each wanted path at most once.

Normalise entry names before comparing — tar entries appear as `lib/apk/db/installed`,
`./lib/apk/db/installed`, and occasionally with a trailing slash for directories. Comparing
raw names makes a lookup miss depending on which tool built the image, and a miss here is an
empty inventory rather than an error.

- [ ] **Step 4: Run the tests, then commit**

```bash
git add internal/source/walk.go internal/source/walk_test.go
git commit -m "feat: resolve files across layers, honouring whiteouts"
```

---

## Task 3: `/etc/os-release`

**Files:**
- Create: `internal/cataloger/osrelease/osrelease.go`, `…/osrelease_test.go`

**Interfaces:**
- Produces: `func Parse(r io.Reader) (pkgmeta.Distro, error)`

The format is shell-ish `KEY=VALUE`, values optionally double- or single-quoted. Only three
keys matter: `ID`, `VERSION_ID`, `PRETTY_NAME`. Everything else is ignored rather than
rejected — the file carries URLs and vendor fields that vary by distro.

- [ ] **Step 1: Write the failing test**

```go
func TestParse(t *testing.T) {
	const real = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.19.9
PRETTY_NAME="Alpine Linux v3.19"
HOME_URL="https://alpinelinux.org/"
`
	d, err := Parse(strings.NewReader(real))
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != "alpine" || d.VersionID != "3.19.9" || d.PrettyName != "Alpine Linux v3.19" {
		t.Errorf("Parse = %+v", d)
	}
	// The value that actually matters is the key it produces.
	eco, err := d.Ecosystem()
	if err != nil || eco != "Alpine:v3.19" {
		t.Errorf("Ecosystem() = %q, %v; want Alpine:v3.19", eco, err)
	}
}

// Quoting is not optional to handle: PRETTY_NAME is quoted and VERSION_ID is
// not, in the same real file. Keeping the quotes turns "3.19.9" into
// `"3.19.9"`, which fails the X.Y check and reports every package skipped.
func TestParse_Quoting(t *testing.T) { /* bare, double-quoted, single-quoted */ }

// A file with no ID yields a zero Distro and no error: it is the caller's job
// to decide, and Distro.Ecosystem() already refuses to key an empty ID.
func TestParse_MissingFieldsAreNotAnError(t *testing.T) { /* … */ }

// Comments and blank lines appear in real files.
func TestParse_IgnoresCommentsAndBlanks(t *testing.T) { /* … */ }
```

- [ ] **Steps 2-4: fail, implement, pass, commit**

```bash
git commit -m "feat: read the distro from /etc/os-release"
```

---

## Task 4: `/lib/apk/db/installed`

**Files:**
- Create: `internal/cataloger/apkdb/apkdb.go`, `…/apkdb_test.go`,
  `internal/cataloger/apkdb/testdata/installed`

**Interfaces:**
- Consumes: `pkgmeta.Package`, `pkgmeta.SourcePackage`, `pkgmeta.Distro`
- Produces: `func Parse(r io.Reader, ecosystem string) ([]pkgmeta.Package, error)`

### The format, and the trap in it

Records are separated by a blank line; every line is `<letter>:<value>`. Four fields matter:

| Key | Becomes |
|---|---|
| `P` | `Package.Name` |
| `V` | `Package.Version` |
| `o` | `Package.Source.Name` — **this is D8** |
| `A` | architecture; recorded but not part of the key |

**Keys are case-sensitive and the cases mean different things.** `A:` is the package
architecture, `a:` is a *file's* owner/permission triple. `T:` is the description, `t:` is
the build timestamp. In the real 15-record file there are 57 `a:` lines against 15 `A:`
lines, so a parser that folds case reads file permissions as architectures on the majority
of lines. Dispatch on the byte, never on a case-folded copy.

Set `Ecosystem` from the caller's argument, which comes from `Distro.Ecosystem()` — a
package cannot derive it (D6, D7).

- [ ] **Step 1: Build the fixture**

Extract the real file from the alpine:3.19 layer and commit it. It is ~15 KB and it is the
only way this parser is tested against the shapes that actually occur:

```bash
# The layer is already fetched during the Task 1 e2e; otherwise pull it again.
```

Confirm it is tracked — `.gitignore` has rules that could swallow it:

```bash
git check-ignore -v internal/cataloger/apkdb/testdata/installed || echo "not ignored - good"
```

- [ ] **Step 2: Write the failing tests**

```go
// The real file, all 15 records, matching what syft reports for this image.
func TestParse_RealDatabase(t *testing.T) {
	f, err := os.Open("testdata/installed")
	// … expect 15 packages
	// alpine-baselayout 3.4.3-r2, source alpine-baselayout
	// and every package carries a non-nil Source (all 15 have o:)
}

// D8, on the packages that actually diverge in this image.
func TestParse_SourcePackageDiffersFromBinary(t *testing.T) {
	// busybox-binsh -> busybox, ssl_client -> busybox, musl-utils -> musl
}

// The case trap: 57 `a:` lines against 15 `A:` in the real file. A parser that
// upper-cases keys reads a file's owner triple as the package architecture and
// produces packages whose fields are permission bits.
func TestParse_KeysAreCaseSensitive(t *testing.T) {
	const rec = "P:x\nV:1-r0\nA:x86_64\no:x\na:0:0:755\nt:1695795276\nT:desc\n"
	// expect Arch "x86_64", not "0:0:755"
}

// Records are separated by a blank line, and the file ends with one.
func TestParse_RecordBoundaries(t *testing.T) { /* trailing blank line, doubled blanks */ }

// A record with no P: is not a package. Emitting one with an empty name gives
// the matcher a lookup key of "" that can only ever miss.
func TestParse_RecordWithoutNameIsSkipped(t *testing.T) { /* … */ }
```

- [ ] **Steps 3-5: fail, implement, pass**

- [ ] **Step 6: Commit**

```bash
git commit -m "feat: catalog apk packages from /lib/apk/db/installed"
```

---

## Task 5: Wire it into `assay scan`

**Files:**
- Modify: `internal/scancmd/scancmd.go`, `internal/scancmd/scancmd_test.go`,
  `cmd/assay/main.go`

`scan` currently opens its argument as a CycloneDX file. It must now decide:

1. an explicit `docker-archive:` / `oci-dir:` prefix → image
2. an existing file path → SBOM, exactly as today
3. otherwise → registry reference

Build the `Target` from the image path: `Distro` from `/etc/os-release`, packages from
`/lib/apk/db/installed`, `Ecosystem` from `Distro.Ecosystem()`, `Location.LayerDigest` from
the diff ID of the layer each file came from.

**An image with no `/etc/os-release`, or a distro with no ecosystem, exits 2** — not 0 with
an empty inventory. 2a's `report.Table` already produces that outcome from a `Target` whose
packages carry an empty `Ecosystem`; the job here is to reach it rather than to return early
with a nil error.

- [ ] **Step 1: Write the failing tests**

```go
// The three target kinds reach three different loaders, and an SBOM path still
// works exactly as it did in 2a.
func TestRun_TargetKinds(t *testing.T) { /* table over a temp SBOM, a temp tar, a ref */ }

// A target we cannot read is exit 2 with a message naming the target, never a
// clean empty scan (D11).
func TestRun_UnreadableTargetExits2(t *testing.T) { /* … */ }

// An image with no os-release yields packages with no ecosystem, which the
// report already turns into "not evaluated" and exit 2.
func TestRun_ImageWithoutOSReleaseIsNotClean(t *testing.T) { /* … */ }
```

- [ ] **Steps 2-4: fail, implement, pass, commit**

---

## Task 6: End-to-end, and the differential that matters

- [ ] **Step 1: The 2a differential — the primary check**

```bash
export ASSAY_DB_DIR=$(mktemp -d)
go run ./cmd/assay db update

syft alpine:3.19 -o cyclonedx-json > alpine.cdx.json
go run ./cmd/assay scan alpine.cdx.json > via-sbom.txt
go run ./cmd/assay scan alpine:3.19        > via-image.txt
diff via-sbom.txt via-image.txt
```

**These should agree exactly**, and any divergence is ours alone: same database, same
matcher, same comparer, same image. Compare the finding sets, the package count, and the
`Location.LayerDigest` values. Investigate every difference before explaining any of it away.

Expected from the 2a run: 10 findings, 15 packages, one component not evaluated. Note that
the SBOM has 16 components against the image's 15 packages — syft emits an
`operating-system` component that 2a counts and excludes. The image path has no such
component, so **the totals will legitimately differ by one**; the findings must not.

- [ ] **Step 2: The three sources agree**

```bash
docker save alpine:3.19 -o alpine.tar
go run ./cmd/assay scan docker-archive:alpine.tar > via-tar.txt
diff via-image.txt via-tar.txt
```

The same image through a registry and through a tarball is the same image. A difference
means the layer walk depends on how the layers were delivered.

- [ ] **Step 3: grype, for the outside view**

```bash
grype alpine:3.19 -o json > grype.json
```

Compare CVE sets against grype's distro-namespace matches, as 2a did. 10/10 is the
expectation, since the database and matcher are unchanged.

- [ ] **Step 4: Mutation-test this slice's own claims**

Each must turn the suite red. A mutation that fails to *compile* has not been tested — keep
the symbol alive and re-run.

| Mutation | Must fail |
|---|---|
| layer walk goes base-first instead of newest-first | Task 2 |
| `.wh.` markers ignored | Task 2 |
| `.wh..wh..opq` treated as an ordinary whiteout | Task 2 |
| whiteout entries returned as files | Task 2 |
| `Location.LayerDigest` set from the manifest digest, not the diff ID | Task 1/5 |
| apk keys folded to upper case | Task 4 |
| `o:` not read, so `Package.Source` stays nil | Task 4 |
| os-release values keep their quotes | Task 3 |
| platform selection accepts `unknown/unknown` | Task 1 |

- [ ] **Step 5: Update the docs, both languages, same commit**

- README: `assay scan alpine:3.19` works; the three sources; the daemon exclusion and why.
  The roadmap section ②b ticks.
- `docs/deferred-decisions.md`: 2b moves out of "Next work"; add the Docker daemon source as
  a new deferral with the measured module counts.

- [ ] **Step 6: Commit**

---

## Done when

- `assay scan alpine:3.19` and `assay scan alpine.cdx.json` produce the same findings
- The same image through registry, tarball, and OCI layout produces the same findings
- A package deleted in a later layer is absent from the inventory
- `Location.LayerDigest` matches what syft reports for the same package
- An image with no readable distro exits 2, never 0
- Every mutation in Task 6 Step 4 turns the suite red
- `pkg/v1/daemon` is not in the build

## Not in this slice

The Docker daemon source (D19), Debian and RHEL catalogers, `--fail-on`, and JSON output.
Squashed filesystems, non-`linux` platforms, and image signature verification are not
planned and are not recorded as deferrals — raise them if they become real.
