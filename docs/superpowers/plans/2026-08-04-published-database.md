# Published Database Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A builder builds the vulnerability database once and publishes it as an OCI artifact; everyone else downloads it in seconds instead of spending seven hours rebuilding it.

**Architecture:** `assay db build` keeps today's behaviour under a new name. `assay db push <ref>` packs the bolt file into a single-layer OCI image and writes it to a registry. `assay db update` — which today builds — becomes a pull. `assay db build --seed <ref>` starts from an already-built database instead of an empty one, which is what makes a daily delta possible and what keeps the builder inside GitHub Actions' six-hour job limit.

**Tech Stack:** Go 1.26, `github.com/google/go-containerregistry` (already a direct dependency; `pkg/v1/empty`, `pkg/v1/static`, `pkg/v1/mutate`, `pkg/v1/remote`, and `pkg/registry` for offline tests), `go.etcd.io/bbolt`, stdlib `compress/gzip`.

## Global Constraints

Copied from `CLAUDE.md`. Every task's requirements implicitly include this section.

- **A scan never fetches vulnerability data (D14).** This slice adds network calls to `db update` and `db push` only. `internal/scancmd` and everything it reaches must be untouched. A scan of an SBOM, a `docker-archive:` tarball or a directory still makes no network call at all.
- **Exit codes are contract (D11):** `0` clean, `1` findings at or above `--fail-on`, `2` could not run or the result cannot be trusted. Precedence `2 > 1 > 0`. Every failure in this slice is a `2`.
- **Results to stdout, diagnostics to stderr.** `db update`'s progress goes to stderr.
- **Deterministic output.** No map iteration order may reach a caller or an output stream.
- **`run(args, stdout, stderr) int` is the testable seam.** New commands go in the `run` switch and take writers, never touching `os.Stdout` or `os.Exit`.
- **Freshness is measured from upstream data, not build time (D12).** `Provenance.DataAsOf` survives the round trip; a pulled database reports when its *upstream* data was current, not when it was pulled.
- **Coverage must be reported so "found nothing" is never confused with "was broken" (D20).** Prefer deriving facts from stored data over trusting a self-report.
- **Comments explain *why*.** Match the register of the existing code.
- **Two direct dependencies.** Do not add a third. `oras` and `crane` are not available; everything here is go-containerregistry plus the stdlib.
- **Bilingual docs.** `X.md` and `X.ko.md` change in the same commit. English is canonical. Plans under `docs/superpowers/plans/` are exempt — English only.
- Run `gofmt -l .` (must be empty), `go vet ./...`, and `go test ./...` before every commit. `-race` needs a C toolchain and is not available locally; CI runs it.

## Why this slice exists

Measured 2026-08-03 while building D27: a full NVD sync is about **seven hours**. NVD generates each 2,000-record page in 114–136 seconds, and neither compression (8× fewer bytes, no time saved) nor a smaller page changes the total. That is not a constant anyone can tune away, and it is why NVD shipped opt-in — a seven-hour default is unusable.

Two consequences drive the design:

1. **Seven hours per user is not a database anyone maintains.** grype and trivy both solve this the same way: a builder builds, everyone else downloads.
2. **Seven hours does not fit in a GitHub Actions job either** — the limit is six. But the full pass does not need to happen in CI at all. It happens **once, locally**, where no job cap applies, and the result is pushed as the first artifact. Every scheduled run after that starts from the published artifact and fetches only what changed, which is minutes. That is Task 5, and it is the part that does not exist today: `dbcmd.Update` builds into a fresh store and renames over the live database, so nothing carries forward.

### What the seed carries, and what it must not

**Only the ratings bucket.** Advisories are rebuilt from the providers on every run, without exception.

This is not an optimisation, it is a correctness requirement. OSV archives take minutes, so there is nothing to save by seeding them — and seeding them **makes deletion impossible**. An advisory that upstream later withdraws stops appearing in the archive, but a seeded database already holds it, and nothing in the build removes a record that no provider re-emits. D16 drops withdrawn advisories at ingestion precisely so no code path can forget the check; seeding advisories reintroduces the problem one layer up, as a false positive that never expires.

Ratings do not have that failure mode. A rating is an opinion keyed on a CVE, NVD does not delete CVEs, and a revised score changes the record's `lastModified` so the next delta overwrites it. A stale rating for a CVE no advisory matches is unreachable — `Matcher.annotate` only asks `RatingsFor` about identifiers a finding already carries.

The build must **say** which half it carried forward, on stderr, in the register `db build` already uses for its provider lines. A seeded build that looked identical to a full one would be the same silent over-claim in a new place.

## File Structure

| File | Responsibility |
|---|---|
| `internal/dbartifact/dbartifact.go` (new) | Pack a database file into a `v1.Image` and unpack it back. Media types, annotations, gzip. Knows nothing about registries or the CLI. |
| `internal/dbartifact/dbartifact_test.go` (new) | Round-trip, annotation, and rejection tests. |
| `internal/dbcmd/push.go` (new) | `Push`: resolve a reference, pack, write to a registry or a local file. |
| `internal/dbcmd/pull.go` (new) | `Pull`: fetch, check the schema annotation before downloading the layer, unpack into a temp file, rename. |
| `internal/dbcmd/dbcmd.go` (modify) | `Update` gains a `seed` parameter. Its doc comment stops describing itself as the only way to get a database. |
| `cmd/assay/main.go` (modify) | `db build`, `db push`, `db update` routing; the default artifact reference; `--from`, `--seed`, `--to` flags; usage text. |
| `.github/workflows/db-publish.yml` (new) | Daily: pull yesterday's artifact, layer a bounded NVD delta on it, push. |
| `README.md` / `README.ko.md`, roadmap, `docs/deferred-decisions.md` / `.ko.md` (modify) | D28, slice ⑧ marked done, the OCI deferral resolved. |

`dbartifact` is deliberately separate from `dbcmd`: packing is pure and fully testable without a registry, a CLI, or a filesystem beyond one temp file. `push.go` and `pull.go` are separate files rather than more of `dbcmd.go`, which is already 350 lines and covers two unrelated commands.

---

### Task 1: Rename `db update` to `db build`

`db update` currently builds from source. It is about to mean "download", so the building behaviour needs its own name first, in its own commit, with nothing else changing. Doing the rename and the new behaviour together makes the diff impossible to review.

**Files:**
- Modify: `cmd/assay/main.go` (the `db` switch, and `usage`)
- Test: `cmd/assay/main_test.go`

**Interfaces:**
- Consumes: `dbcmd.Update(ctx, dbPath, providers, annotators, stdout, stderr) int` — unchanged in this task.
- Produces: `db build` as the source-building subcommand. Task 4 gives `db update` its new meaning; until then `db update` must fail loudly rather than silently doing the old thing.

- [ ] **Step 1: Write the failing test**

In `cmd/assay/main_test.go`:

```go
// `db build` is the source-building command. `db update` used to be, and is
// about to mean "download the published database" instead. Between those two
// states it must not quietly keep building: someone's cron job would go on
// working and then change meaning under them without ever erroring.
func TestRun_DBBuildReplacesUpdate(t *testing.T) {
	t.Run("build is a known subcommand", func(t *testing.T) {
		// Pointed at a directory that cannot be created: `blocker` is a
		// regular file, so MkdirAll on a path beneath it fails. Update
		// creates the database directory BEFORE it touches a provider, so
		// this returns immediately.
		//
		// That precaution is the whole reason this subtest is written this
		// way. The first version just called `db build` and asserted on the
		// error -- and with ASSAY_DB_DIR unset, store.DefaultPath resolves
		// to the user's real cache, so the test performed an actual build:
		// ~200 MB fetched from the live OSV endpoint, 183 seconds, and the
		// developer's real database overwritten by `go test ./...`. A
		// routing assertion must not be able to do that.
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("ASSAY_DB_DIR", filepath.Join(blocker, "sub"))

		var stdout, stderr bytes.Buffer
		run([]string{"db", "build"}, &stdout, &stderr)
		if strings.Contains(stderr.String(), "unknown db subcommand") {
			t.Errorf("db build is not routed:\n%s", stderr.String())
		}
	})

	t.Run("update does not silently build", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"db", "update"}, &stdout, &stderr)
		if code != exitError {
			t.Errorf("db update = %d, want %d until Task 4 gives it a meaning", code, exitError)
		}
		if !strings.Contains(stderr.String(), "db build") {
			t.Errorf("stderr does not point at the new name:\n%s", stderr.String())
		}
	})
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `go test -run TestRun_DBBuildReplacesUpdate ./cmd/assay/ -v`
Expected: FAIL — `db build` is routed to the `default` case, so stderr says "unknown db subcommand".

- [ ] **Step 3: Rename the case**

In `cmd/assay/main.go`, in the `db` switch, change `case "update":` to `case "build":` and add:

```go
case "update":
	// Deliberately not an alias. `update` is about to mean "download the
	// published database" (D28), and a cron job that keeps building
	// because the old name still works would change behaviour under its
	// owner the day the new meaning lands, with nothing in between saying
	// so. Failing now is the only version of this that is visible.
	fmt.Fprintln(stderr, "error: `db update` now downloads the published database, which is not wired up yet")
	fmt.Fprintln(stderr, "  to build from source, use `assay db build`")
	return exitError
```

- [ ] **Step 4: Update `usage`**

In the command list, replace the `db update` line with:

```
  db build        Build the vulnerability database from its upstream sources
  db status       Show what is in the database and how current it is
```

- [ ] **Step 5: Run the whole suite**

Run: `go test ./... && gofmt -l . && go vet ./...`
Expected: PASS, empty gofmt output. Fix any other test that invoked `db update` expecting a build.

- [ ] **Step 6: Commit**

```bash
git add cmd/assay/main.go cmd/assay/main_test.go
git commit -m "refactor: db update becomes db build

Its own commit and nothing else in it: update is about to mean download,
and reviewing a rename tangled with a behaviour change is not possible.
update fails loudly in the meantime rather than aliasing to build, so a
cron job cannot keep working and then silently change meaning."
```

---

### Task 2: Pack and unpack the database as an OCI image

**Files:**
- Create: `internal/dbartifact/dbartifact.go`
- Test: `internal/dbartifact/dbartifact_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks. `store.SchemaVersion` (an `int`) and `store.Meta` (for `BuiltAt` and per-provider `DataAsOf`) from `internal/store`.
- Produces:
  ```go
  const (
      MediaTypeLayer  = "application/vnd.assay.db.layer.v1+gzip"
      MediaTypeConfig = "application/vnd.assay.db.config.v1+json"

      AnnotationSchema   = "dev.assay.schema-version"
      AnnotationBuiltAt  = "dev.assay.built-at"
      AnnotationDataAsOf = "dev.assay.data-as-of"
  )

  type Meta struct {
      SchemaVersion int
      BuiltAt       time.Time
      DataAsOf      time.Time
  }

  func Pack(dbPath string, m Meta) (v1.Image, error)
  func Unpack(img v1.Image, destPath string) error
  func MetaOf(img v1.Image) (Meta, error)
  ```

**Design notes for the implementer:**

The metadata lives in **manifest annotations**, not in the config blob. go-containerregistry's `mutate.ConfigFile` takes a `v1.ConfigFile` (the Docker/OCI runtime config shape), which has nowhere sensible to put a schema version; fighting that to write arbitrary config bytes needs a custom `v1.Image` implementation. `mutate.Annotations` is the supported path, `crane manifest` displays the result, and — the reason that matters — **a puller can read them from the manifest alone, without downloading the layer.** A schema mismatch must not cost a 60 MB download.

`static.NewLayer(b, mediaType)` stores `b` verbatim: both `Compressed()` and `Uncompressed()` return exactly those bytes. So gzip explicitly before constructing the layer and gunzip explicitly on the way out. The media type says `+gzip` because that is what the bytes are.

- [ ] **Step 1: Write the failing round-trip test**

Create `internal/dbartifact/dbartifact_test.go`:

```go
package dbartifact

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestPackUnpack_RoundTripsTheExactBytes(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vulnerability.db")
	// Deliberately not valid bolt: Pack must move bytes, not interpret
	// them. A Pack that understood the format could not round-trip a
	// database written by a newer schema.
	want := []byte("bolt-ish bytes \x00\x01\x02 and some repetition to compress")
	if err := os.WriteFile(src, want, 0o644); err != nil {
		t.Fatal(err)
	}

	m := Meta{
		SchemaVersion: 6,
		BuiltAt:       time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC),
		DataAsOf:      time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
	}
	img, err := Pack(src, m)
	if err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(dir, "out.db")
	if err := Unpack(img, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("round trip changed the bytes:\n got %q\nwant %q", got, want)
	}
}

// The metadata must be readable from the MANIFEST, without pulling the
// layer: a schema mismatch is the common case for an out-of-date client,
// and discovering it after a 60 MB download is the wrong order.
func TestMetaOf_ReadsAnnotationsWithoutTheLayer(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vulnerability.db")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := Meta{
		SchemaVersion: 6,
		BuiltAt:       time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC),
		DataAsOf:      time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
	}
	img, err := Pack(src, want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := MetaOf(img)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != want.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", got.SchemaVersion, want.SchemaVersion)
	}
	if !got.BuiltAt.Equal(want.BuiltAt) {
		t.Errorf("BuiltAt = %v, want %v", got.BuiltAt, want.BuiltAt)
	}
	// D12: freshness is the upstream timestamp, and it has to survive the
	// round trip separately from BuiltAt. A pulled database that reported
	// its pull time as its freshness would call a stale mirror current.
	if !got.DataAsOf.Equal(want.DataAsOf) {
		t.Errorf("DataAsOf = %v, want %v", got.DataAsOf, want.DataAsOf)
	}

	// And the annotations are on the manifest itself, reachable without
	// touching layer bytes.
	mf, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if mf.Annotations[AnnotationSchema] != strconv.Itoa(want.SchemaVersion) {
		t.Errorf("manifest annotations = %v, want %s to be %d",
			mf.Annotations, AnnotationSchema, want.SchemaVersion)
	}
}

// An image that is not one of ours must be refused by name rather than
// producing a corrupt database file. The failure mode this prevents is a
// scan running happily against garbage.
func TestUnpack_RejectsAnImageThatIsNotADatabase(t *testing.T) {
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:     static.NewLayer([]byte("not a database"), types.OCILayer),
		MediaType: types.OCILayer,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = Unpack(img, filepath.Join(t.TempDir(), "out.db"))
	if err == nil {
		t.Fatal("Unpack accepted an image with no assay layer")
	}
	if !strings.Contains(err.Error(), MediaTypeLayer) {
		t.Errorf("error %q does not name the media type it wanted", err)
	}
}
```

Add `"strings"` to the imports.

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./internal/dbartifact/`
Expected: FAIL to build — `dbartifact.go` does not exist.

- [ ] **Step 3: Implement**

Create `internal/dbartifact/dbartifact.go`:

```go
// Package dbartifact packs a built vulnerability database into an OCI image
// and unpacks it again. It is what makes a database something a builder
// publishes once rather than something every user spends seven hours
// rebuilding (D28).
//
// It knows nothing about registries, the CLI, or bolt. Packing is moving
// bytes: a Pack that understood the database format could not round-trip a
// file written by a newer schema, which is exactly the case a client needs
// to detect and refuse rather than misread.
package dbartifact

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	// MediaTypeLayer says the single layer is a gzipped bolt file. The
	// +gzip is not decorative: static.NewLayer stores bytes verbatim, so
	// whatever compression happens is done here and has to be declared.
	MediaTypeLayer = "application/vnd.assay.db.layer.v1+gzip"
	// MediaTypeConfig marks the manifest's config blob. OCI requires a
	// config descriptor even when there is nothing runtime-ish to say, and
	// a distinct type keeps this artifact from being mistaken for a
	// runnable image by anything that inspects it.
	MediaTypeConfig = "application/vnd.assay.db.config.v1+json"

	// Metadata lives in manifest annotations rather than the config blob,
	// because a client can read the manifest without downloading the
	// layer. A schema mismatch is the ordinary case for an out-of-date
	// binary, and finding out after a 60 MB download is the wrong order.
	AnnotationSchema   = "dev.assay.schema-version"
	AnnotationBuiltAt  = "dev.assay.built-at"
	AnnotationDataAsOf = "dev.assay.data-as-of"
)

// Meta is what a puller can learn before committing to the download.
type Meta struct {
	SchemaVersion int
	// BuiltAt is when this artifact was assembled; DataAsOf is when the
	// UPSTREAM data it holds was current. They are separate for the reason
	// D12 gives: a mirror serving a three-month-old snapshot fetched today
	// has a recent BuiltAt and an old DataAsOf, and judging freshness by
	// the former reports stale data as fresh.
	BuiltAt  time.Time
	DataAsOf time.Time
}

// Pack reads the database at dbPath and returns a single-layer OCI image.
func Pack(dbPath string, m Meta) (v1.Image, error) {
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, fmt.Errorf("read database: %w", err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return nil, fmt.Errorf("compress database: %w", err)
	}
	// Closed explicitly rather than deferred: gzip writes its footer on
	// Close, and a deferred Close runs after buf has already been handed
	// to static.NewLayer -- producing a layer that is missing its last
	// bytes and fails to decompress only on the puller's machine.
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("compress database: %w", err)
	}

	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.MediaType(MediaTypeConfig))
	img, err = mutate.Append(img, mutate.Addendum{
		Layer:     static.NewLayer(buf.Bytes(), types.MediaType(MediaTypeLayer)),
		MediaType: types.MediaType(MediaTypeLayer),
	})
	if err != nil {
		return nil, fmt.Errorf("append database layer: %w", err)
	}
	annotated := mutate.Annotations(img, map[string]string{
		AnnotationSchema:   strconv.Itoa(m.SchemaVersion),
		AnnotationBuiltAt:  m.BuiltAt.UTC().Format(time.RFC3339),
		AnnotationDataAsOf: m.DataAsOf.UTC().Format(time.RFC3339),
	})
	out, ok := annotated.(v1.Image)
	if !ok {
		return nil, fmt.Errorf("annotating produced %T, not a v1.Image", annotated)
	}
	return out, nil
}

// MetaOf reads what Pack recorded, from the manifest alone.
func MetaOf(img v1.Image) (Meta, error) {
	mf, err := img.Manifest()
	if err != nil {
		return Meta{}, fmt.Errorf("read manifest: %w", err)
	}
	raw, ok := mf.Annotations[AnnotationSchema]
	if !ok {
		return Meta{}, fmt.Errorf("manifest has no %s annotation: this is not an assay database artifact", AnnotationSchema)
	}
	schema, err := strconv.Atoi(raw)
	if err != nil {
		return Meta{}, fmt.Errorf("%s is %q, not a number", AnnotationSchema, raw)
	}
	m := Meta{SchemaVersion: schema}
	// Timestamps are best-effort on read: a missing or malformed one is
	// reported as zero rather than failing the pull. The schema version is
	// the field correctness depends on; these two are for display, and
	// refusing a usable database because its BuiltAt was malformed would
	// trade a real capability for a cosmetic guarantee.
	if t, err := time.Parse(time.RFC3339, mf.Annotations[AnnotationBuiltAt]); err == nil {
		m.BuiltAt = t
	}
	if t, err := time.Parse(time.RFC3339, mf.Annotations[AnnotationDataAsOf]); err == nil {
		m.DataAsOf = t
	}
	return m, nil
}

// Unpack writes the database held by img to destPath.
func Unpack(img v1.Image, destPath string) error {
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("read layers: %w", err)
	}
	for _, l := range layers {
		mt, err := l.MediaType()
		if err != nil {
			return fmt.Errorf("read layer media type: %w", err)
		}
		if string(mt) != MediaTypeLayer {
			continue
		}
		rc, err := l.Compressed()
		if err != nil {
			return fmt.Errorf("open layer: %w", err)
		}
		defer rc.Close()
		zr, err := gzip.NewReader(rc)
		if err != nil {
			return fmt.Errorf("decompress database: %w", err)
		}
		defer zr.Close()
		f, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("create %s: %w", destPath, err)
		}
		defer f.Close()
		if _, err := io.Copy(f, zr); err != nil {
			return fmt.Errorf("write database: %w", err)
		}
		return f.Close()
	}
	return fmt.Errorf("no layer of type %s: this is not an assay database artifact", MediaTypeLayer)
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/dbartifact/ -v`
Expected: all three PASS.

- [ ] **Step 5: Prove the tests can fail**

Run each of these, confirm the suite goes RED, then revert:

1. In `Pack`, drop the `zw.Close()` call (assign it to `_` so the build stays valid: `_ = zw.Close()` before `buf.Bytes()` becomes `var b = buf.Bytes()` taken before the close — rewrite so every identifier stays used). Expect the round-trip test to fail on truncated gzip.
2. In `Unpack`, change `if string(mt) != MediaTypeLayer { continue }` to `if false { continue }`. Expect `TestUnpack_RejectsAnImageThatIsNotADatabase` to fail.
3. In `Pack`, drop `AnnotationDataAsOf` from the annotations map. Expect `TestMetaOf_ReadsAnnotationsWithoutTheLayer` to fail on `DataAsOf`.

If any stays green, the test is documentation rather than coverage — fix the test before moving on. Record the result of each in your report.

- [ ] **Step 6: Commit**

```bash
git add internal/dbartifact/
git commit -m "feat: pack the database as an OCI artifact

Metadata goes in manifest annotations rather than the config blob, so a
client can read the schema version without downloading the layer -- a
mismatched schema is the ordinary case for an out-of-date binary, and
finding out after a 60 MB download is the wrong order.

Packing moves bytes and does not interpret them: a Pack that understood
bolt could not round-trip a file written by a newer schema, which is the
case a client has to detect and refuse rather than misread."
```

---

### Task 3: `assay db push <ref>`

**Files:**
- Create: `internal/dbcmd/push.go`
- Create: `internal/dbcmd/push_test.go`
- Modify: `cmd/assay/main.go`

**Interfaces:**
- Consumes: `dbartifact.Pack`, `dbartifact.Meta` (Task 2); `store.Open`, `store.Meta`, `store.SchemaVersion`.
- Produces: `func Push(ctx context.Context, dbPath, ref string, stdout, stderr io.Writer) int`.

**Design notes:** `Push` reads the local database's `store.Meta` to fill the artifact annotations, so the published freshness is the database's own, never `time.Now()`. `DataAsOf` for the artifact is the **oldest** of the per-provider timestamps — the same "the oldest upstream wins" rule the NVD provider already uses across pages (D12): an artifact is only as fresh as its stalest component, and reporting the newest would let one recently-synced provider vouch for a stale one.

- [ ] **Step 1: Write the failing test**

Create `internal/dbcmd/push_test.go`:

```go
package dbcmd

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// pushable builds a real database on disk and returns its path.
func pushable(t *testing.T, dataAsOf time.Time) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt: time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{
			"osv": {Source: "https://example.test", DataAsOf: dataAsOf},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// The whole point of the slice: a built database becomes something a
// registry serves. Tested against go-containerregistry's own in-memory
// registry, so this needs no network and no credentials.
func TestPush_WritesAPullableArtifact(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	host := must(t, u, err).Host
	ref := host + "/assay-db:v6"

	asOf := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	path := pushable(t, asOf)

	var out, errOut bytes.Buffer
	if code := Push(context.Background(), path, ref, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	parsedRef, refErr := name.ParseReference(ref)
	img, err := remote.Image(must(t, parsedRef, refErr))
	if err != nil {
		t.Fatalf("pushed artifact is not pullable: %v", err)
	}
	m, err := dbartifact.MetaOf(img)
	if err != nil {
		t.Fatal(err)
	}
	if m.SchemaVersion != store.SchemaVersion {
		t.Errorf("published schema = %d, want %d", m.SchemaVersion, store.SchemaVersion)
	}
	// D12: the artifact carries the UPSTREAM freshness, not the moment it
	// was pushed. Asserting this is what stops a mirror that re-pushes an
	// old database from presenting it as current.
	if !m.DataAsOf.Equal(asOf) {
		t.Errorf("published DataAsOf = %v, want the database's own %v", m.DataAsOf, asOf)
	}
}

// An artifact is only as fresh as its stalest provider. Reporting the
// newest would let one recently-synced source vouch for a stale one.
func TestPush_DataAsOfIsTheOldestProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	if err := w.SetMeta(store.Meta{
		BuiltAt: time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{
			"fresh": {DataAsOf: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)},
			"stale": {DataAsOf: old},
		},
	}); err != nil {
		t.Fatal(err)
	}
	w.Close()

	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, uerr := url.Parse(srv.URL)
	ref := must(t, u, uerr).Host + "/assay-db:v6"

	var out, errOut bytes.Buffer
	if code := Push(context.Background(), path, ref, &out, &errOut); code != 0 {
		t.Fatalf("Push = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	parsedRef, refErr := name.ParseReference(ref)
	img, err := remote.Image(must(t, parsedRef, refErr))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := dbartifact.MetaOf(img)
	if !m.DataAsOf.Equal(old) {
		t.Errorf("DataAsOf = %v, want the OLDEST provider's %v", m.DataAsOf, old)
	}
}

// Pushing a database that is not there is a 2 that says so, not a panic
// and not a silent empty artifact.
func TestPush_MissingDatabaseExitsTwo(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, uerr := url.Parse(srv.URL)
	ref := must(t, u, uerr).Host + "/assay-db:v6"

	var out, errOut bytes.Buffer
	code := Push(context.Background(), filepath.Join(t.TempDir(), "absent.db"), ref, &out, &errOut)
	if code != 2 {
		t.Errorf("Push with no database = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "absent.db") {
		t.Errorf("stderr does not name the missing file:\n%s", errOut.String())
	}
}

func must[T any](t *testing.T, v T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return v
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./internal/dbcmd/ -run TestPush`
Expected: FAIL to build — `Push` is undefined.

- [ ] **Step 3: Implement `Push`**

Create `internal/dbcmd/push.go`:

```go
package dbcmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// Push publishes the database at dbPath to ref (D28). It is the builder's
// half of the slice: one machine spends the hours, everyone else pulls the
// result in seconds.
//
// The artifact's freshness comes from the database's own recorded
// provenance, never from the clock. Stamping time.Now() here would make
// every re-push of an old database look current, which is the exact
// failure D12 separates DataAsOf from BuiltAt to prevent.
func Push(ctx context.Context, dbPath, ref string, stdout, stderr io.Writer) int {
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Fprintf(stderr, "error: no database at %s: %v\n", dbPath, err)
		fmt.Fprintln(stderr, "  build one first with `assay db build`")
		return 2
	}
	db, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: open database: %v\n", err)
		return 2
	}
	meta, err := db.Meta()
	if err != nil {
		db.Close()
		fmt.Fprintf(stderr, "error: read database metadata: %v\n", err)
		return 2
	}
	db.Close()

	img, err := dbartifact.Pack(dbPath, dbartifact.Meta{
		SchemaVersion: store.SchemaVersion,
		BuiltAt:       meta.BuiltAt,
		DataAsOf:      oldestDataAsOf(meta),
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: pack database: %v\n", err)
		return 2
	}

	target, err := name.ParseReference(ref)
	if err != nil {
		fmt.Fprintf(stderr, "error: %q is not a valid reference: %v\n", ref, err)
		return 2
	}
	fmt.Fprintf(stderr, "pushing to %s…\n", target)
	if err := remote.Write(target, img,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		fmt.Fprintf(stderr, "error: push: %v\n", err)
		return 2
	}
	digest, err := img.Digest()
	if err != nil {
		fmt.Fprintf(stderr, "error: read digest: %v\n", err)
		return 2
	}
	// The digest goes to stdout because it is the result -- a caller
	// pinning this build in a manifest wants to capture it, and stream
	// discipline says a capturable result is not a diagnostic.
	fmt.Fprintf(stdout, "%s@%s\n", target.Context().Name(), digest)
	return 0
}

// oldestDataAsOf is "the oldest upstream wins" (D12), the same rule the NVD
// provider applies across its own pages: an artifact is only as fresh as
// its stalest component. Taking the newest would let one recently-synced
// provider vouch for a database whose other half is months old.
func oldestDataAsOf(m store.Meta) time.Time {
	var oldest time.Time
	for _, p := range m.Providers {
		if p.DataAsOf.IsZero() {
			continue
		}
		if oldest.IsZero() || p.DataAsOf.Before(oldest) {
			oldest = p.DataAsOf
		}
	}
	return oldest
}
```

- [ ] **Step 4: Route it in the CLI**

In `cmd/assay/main.go`, add to the `db` switch:

```go
case "push":
	if len(args) < 3 {
		fmt.Fprintln(stderr, "error: db push needs a reference, e.g. ghcr.io/kun9497/assay-db:v6")
		return exitError
	}
	return dbcmd.Push(context.Background(), path, args[2], stdout, stderr)
```

And add to `usage`, under the command list:

```
  db push <ref>   Publish the built database as an OCI artifact (builders only)
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/dbcmd/ ./cmd/assay/ && gofmt -l . && go vet ./...`
Expected: PASS, empty gofmt output.

- [ ] **Step 6: Prove the freshness test can fail**

Change `DataAsOf: oldestDataAsOf(meta)` to `DataAsOf: time.Now().UTC()` and confirm both `TestPush_WritesAPullableArtifact` and `TestPush_DataAsOfIsTheOldestProvider` go RED. Then change `oldestDataAsOf`'s comparison from `Before` to `After` and confirm `TestPush_DataAsOfIsTheOldestProvider` alone goes RED. Revert both. Record the results in your report.

- [ ] **Step 7: Commit**

```bash
git add internal/dbcmd/push.go internal/dbcmd/push_test.go cmd/assay/main.go
git commit -m "feat: assay db push publishes the database as an OCI artifact

Tested against go-containerregistry's in-memory registry, so push has real
coverage without a network or credentials.

The artifact's DataAsOf is the OLDEST provider's, not the clock's: an
artifact is only as fresh as its stalest component, and stamping now()
would make every re-push of an old database look current (D12)."
```

---

### Task 4: `assay db update` pulls

**Files:**
- Create: `internal/dbcmd/pull.go`
- Create: `internal/dbcmd/pull_test.go`
- Modify: `cmd/assay/main.go`

**Interfaces:**
- Consumes: `dbartifact.MetaOf`, `dbartifact.Unpack` (Task 2); `Push` (Task 3) for test fixtures; `store.SchemaVersion`.
- Produces: `func Pull(ctx context.Context, dbPath, ref string, stdout, stderr io.Writer) int` and `const DefaultRef = "ghcr.io/kun9497/assay-db"`.

**Design notes:**

- The **tag encodes the schema version** — `ghcr.io/kun9497/assay-db:v6` — mirroring `store.DefaultPath`, which already derives its directory from `SchemaVersion`. A v7 binary asks for `:v7` and gets a clean 404 rather than a v6 database it would misread. The schema annotation is checked as well, *before* the layer is fetched, because a mis-tagged artifact is the case the tag cannot catch.
- **Temp file then rename**, exactly as `Update` does: a failed pull must never leave a half-written database where a scan will find it.
- **Never auto-pull from a scan** (D14). This runs only from `db update`.

**A Go-syntax correction to the test code below.** `must(t, url.Parse(srv.URL))` does not compile: Go forbids mixing an ordinary argument with a spread multi-value call. Capture the pair into locals first and pass both explicitly — `u, err := url.Parse(srv.URL)` then `must(t, u, err)`. Task 3 hit this and settled on that form; `internal/dbcmd/push_test.go` already has the `must` helper and the working call shape. Reuse the existing helper rather than redefining it.

- [ ] **Step 1: Write the failing test**

Create `internal/dbcmd/pull_test.go`:

```go
package dbcmd

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// published pushes a real database to an in-memory registry and returns its
// reference, so pull tests exercise the actual artifact Push writes rather
// than a hand-built approximation that could drift from it.
func published(t *testing.T, schema int) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	host := must(t, u, err).Host
	ref := host + "/assay-db:v" + itoa(schema)

	src := pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC))
	img, err := dbartifact.Pack(src, dbartifact.Meta{
		SchemaVersion: schema,
		BuiltAt:       time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC),
		DataAsOf:      time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	parsedRef, refErr := name.ParseReference(ref)
	if err := remote.Write(must(t, parsedRef, refErr), img); err != nil {
		t.Fatal(err)
	}
	return ref
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// The slice's payoff: a database arrives without a seven-hour build, and it
// is a database -- Open accepts it and Status can read it.
func TestPull_LandsAUsableDatabase(t *testing.T) {
	ref := published(t, store.SchemaVersion)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, &out, &errOut); code != 0 {
		t.Fatalf("Pull = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	db, err := store.Open(dst)
	if err != nil {
		t.Fatalf("pulled file is not a usable database: %v", err)
	}
	defer db.Close()
	if _, err := db.Meta(); err != nil {
		t.Errorf("pulled database has no readable metadata: %v", err)
	}
}

// A schema mismatch is refused BEFORE the layer is downloaded, and the
// error says what to do. Serving a v5 database to a v6 binary silently
// would be a scan reading records it cannot interpret.
func TestPull_RefusesAForeignSchemaWithoutDownloading(t *testing.T) {
	ref := published(t, store.SchemaVersion+1)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	code := Pull(context.Background(), dst, ref, &out, &errOut)
	if code != 2 {
		t.Errorf("Pull of a newer schema = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "upgrade") {
		t.Errorf("stderr does not tell the user what to do:\n%s", errOut.String())
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("a refused pull left a file behind")
	}
}

// A pull that fails partway must not replace a working database. This is
// the same guarantee Update gives, and it matters more here: the failure is
// a network one, so it is the common case rather than the rare one.
func TestPull_AFailedPullLeavesTheLiveDatabaseAlone(t *testing.T) {
	dst := pushable(t, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	before, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	// A registry that is not there.
	code := Pull(context.Background(), dst, "127.0.0.1:1/assay-db:v6", &out, &errOut)
	if code != 2 {
		t.Errorf("Pull from an unreachable registry = %d, want 2", code)
	}
	after, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("the live database is gone: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a failed pull modified the live database")
	}
}
```

Add `"fmt"` to the imports.

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./internal/dbcmd/ -run TestPull`
Expected: FAIL to build — `Pull` is undefined.

- [ ] **Step 3: Implement `Pull`**

Create `internal/dbcmd/pull.go`:

```go
package dbcmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// DefaultRef is where `assay db update` looks. The schema version is the
// TAG, mirroring store.DefaultPath deriving its directory from the same
// constant: a binary only ever asks for artifacts it can read, so a schema
// bump produces a clean "not found" rather than a database it would
// misinterpret.
const DefaultRef = "ghcr.io/kun9497/assay-db"

// Ref returns the reference this binary's schema version corresponds to.
func Ref(base string) string {
	return fmt.Sprintf("%s:v%d", base, store.SchemaVersion)
}

// Pull downloads a published database and installs it at dbPath (D28).
//
// This is the only command that fetches a database, and a scan never calls
// it: D14 is not "a scan avoids the network when it can", it is that a scan
// cannot reach vulnerability data at all. A missing database is an exit 2
// with instructions, never an implicit download.
func Pull(ctx context.Context, dbPath, ref string, stdout, stderr io.Writer) int {
	target, err := name.ParseReference(ref)
	if err != nil {
		fmt.Fprintf(stderr, "error: %q is not a valid reference: %v\n", ref, err)
		return 2
	}
	fmt.Fprintf(stderr, "fetching %s…\n", target)
	img, err := remote.Image(target,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		fmt.Fprintf(stderr, "error: fetch %s: %v\n", target, err)
		fmt.Fprintln(stderr, "  to build the database yourself instead, run `assay db build`")
		return 2
	}

	// Checked before the layer is touched. remote.Image is lazy, so this
	// costs a manifest fetch rather than the whole database -- which is the
	// point: a schema mismatch is the ordinary state of an out-of-date
	// binary, and making the user download 60 MB to be told no is a bad
	// trade for one HTTP request.
	m, err := dbartifact.MetaOf(img)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if m.SchemaVersion != store.SchemaVersion {
		fmt.Fprintf(stderr, "error: %s holds schema v%d, but this assay reads v%d\n",
			target, m.SchemaVersion, store.SchemaVersion)
		if m.SchemaVersion > store.SchemaVersion {
			fmt.Fprintln(stderr, "  upgrade assay, or run `assay db build` to build a v"+
				fmt.Sprint(store.SchemaVersion)+" database from source")
		} else {
			fmt.Fprintln(stderr, "  the published database is older than this assay; upgrade the publisher,")
			fmt.Fprintln(stderr, "  or run `assay db build` to build one from source")
		}
		return 2
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		fmt.Fprintf(stderr, "error: create database directory: %v\n", err)
		return 2
	}
	// Written to a temp file and renamed, exactly as Update does. A pull
	// that dies halfway must not leave a truncated database where a scan
	// will find it and report a confident, wrong, clean result.
	tmp := dbPath + ".tmp"
	_ = os.Remove(tmp)
	if err := dbartifact.Unpack(img, tmp); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: unpack database: %v\n", err)
		return 2
	}
	// Opened before it is installed: an artifact that unpacks cleanly but
	// is not a database it can read must fail here, while the previous
	// database is still in place.
	db, err := store.Open(tmp)
	if err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: the downloaded file is not a usable database: %v\n", err)
		return 2
	}
	db.Close()

	if err := os.Rename(tmp, dbPath); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: install database: %v\n", err)
		return 2
	}
	fmt.Fprintf(stderr, "database installed at %s\n", dbPath)
	if !m.DataAsOf.IsZero() {
		fmt.Fprintf(stderr, "upstream data as of %s\n", m.DataAsOf.Format("2006-01-02"))
	}
	return 0
}
```

- [ ] **Step 4: Wire `db update` to it**

In `cmd/assay/main.go`, replace the Task 1 placeholder `case "update":` with:

```go
case "update":
	ref := dbcmd.Ref(dbcmd.DefaultRef)
	// --from takes a full reference including its tag, because someone
	// pointing at a mirror or a pinned digest needs to say exactly what
	// they mean. The default is the only path that derives its own tag.
	if len(args) > 3 && args[2] == "--from" {
		ref = args[3]
	}
	return dbcmd.Pull(context.Background(), path, ref, stdout, stderr)
```

Update `usage`:

```
  db update       Download the published vulnerability database
  db build        Build the vulnerability database from its upstream sources
```

and under the flags section:

```
db update flags:
  --from <ref>    Pull from a different registry reference (a mirror, or a
                  pinned digest). The default derives its tag from the
                  schema version this binary reads.
```

- [ ] **Step 5: Run everything**

Run: `go test ./... && gofmt -l . && go vet ./...`
Expected: PASS, empty gofmt output.

- [ ] **Step 6: Prove the guards can fail**

Run each, confirm RED, revert, and record the result:

1. Delete the `m.SchemaVersion != store.SchemaVersion` block. Expect `TestPull_RefusesAForeignSchemaWithoutDownloading` to fail.
2. Change `dbartifact.Unpack(img, tmp)` to `dbartifact.Unpack(img, dbPath)`. Expect `TestPull_AFailedPullLeavesTheLiveDatabaseAlone` to fail.
3. In `Ref`, change `v%d` to `v%d-nope`. Expect `TestPull_LandsAUsableDatabase` to still pass (it passes an explicit ref) — this is a **gap**, so add an assertion that `Ref(DefaultRef)` ends in the current schema version, then confirm the mutation goes RED.

- [ ] **Step 7: Commit**

```bash
git add internal/dbcmd/pull.go internal/dbcmd/pull_test.go cmd/assay/main.go
git commit -m "feat: assay db update downloads the published database

The schema version is the tag, mirroring store.DefaultPath deriving its
directory from the same constant: a binary only ever asks for artifacts it
can read. The annotation is checked too, before the layer is fetched --
remote.Image is lazy, so a mismatch costs one manifest request instead of
a 60 MB download.

Temp file then rename, and the database is opened before it is installed:
a pull that dies halfway must not leave a truncated file where a scan
would find it and report a confident clean result.

A scan still never fetches anything (D14). This runs only from db update."
```

---

### Task 5: `assay db build --seed <ref>` — carrying the ratings forward

This is what makes a *daily* build possible. The full seven-hour pass runs once, locally, and is pushed; every scheduled run after it starts from that artifact and fetches only what changed. Without seeding, a scheduled build either repeats the seven hours (and exceeds the six-hour job cap) or publishes a database whose NVD coverage is one day wide.

**Read "What the seed carries, and what it must not" above before implementing.** The seed carries the **ratings bucket only**. Advisories are rebuilt from the providers every run, because a seeded advisory that upstream has withdrawn can never be removed and becomes a permanent false positive.

**Files:**
- Modify: `internal/dbcmd/dbcmd.go` (`Update` gains a seed)
- Modify: `internal/dbcmd/dbcmd_test.go`
- Modify: `cmd/assay/main.go`

**Interfaces:**
- Consumes: `Pull` (Task 4) to fetch a seed by reference; `store.Create`, `store.Open`.
- Produces: `func Update(ctx context.Context, dbPath, seedPath string, providers []provider.Provider, annotators []provider.Annotator, stdout, stderr io.Writer) int` — `seedPath` empty means today's behaviour, building from empty.

**API facts you need, verified against the code — the plan text below was written from memory and got these wrong:**

- `store.Create(path)` and `store.Open(path)` both return `(*store.Bolt, error)`. `store.Writer` is an *interface* (`Put`, `PutRating`, `SetMeta`, `Close`), not a struct — `var w *store.Writer` does not compile.
- There is **no** fetch-by-ID method on the store. Advisories are read with `Lookup(ecosystem, name)`, which is what the matcher itself calls. `Bolt`'s full method set is `Close`, `Covers`, `Put`, `PutRating`, `SetMeta`, `Lookup`, `RatingsFor`, `Meta`, `RecordCount`.
- `EachRating` (Step 3) is new; add it to `Bolt`, to the `Store` interface, and to every fake implementing `Store` — the matcher's in-memory fake will stop compiling otherwise.

**Design notes:** the build proceeds exactly as it does today — `store.Create(tmp)`, providers write advisories into an empty store — and the seed's **ratings are copied in before the annotators run**, so a delta overwrites the entries it re-fetches and leaves the rest. Copying ratings rather than opening the seed file for writing is what keeps advisories authoritative: the temp database starts empty, so a withdrawn advisory that is no longer in the archive is simply absent, which is the correct answer.

Reading the seed's ratings needs an iterator the store does not have yet: `func (b *Bolt) EachRating(fn func(advisory.Rating) error) error`, walking `bucketRatings` in key order. Key order is deterministic in bbolt, so this adds no nondeterminism.

**The hazard to guard:** a seeded build must not report the seed's coverage as its own. If the seed's ratings cover 30 days and this run refreshed one, `db status` must not imply the whole database was refreshed today. `Provenance.Window` (D27) exists for exactly this: an annotator that *ran* replaces its provenance, and the count beside it is still derived from the bucket (D20), so the merged count and the narrower window appear together — which is the honest reading. Test both directions.

**The disclosure:** `db build --seed` prints, on stderr, what it carried forward and what it rebuilt. Concretely: `seeded 21460 rating(s) from <ref>; advisories rebuilt from source`. A seeded build that printed the same thing as a full one is the over-claim this project keeps re-learning.

- [ ] **Step 1: Write the failing test**

Add to `internal/dbcmd/dbcmd_test.go`:

```go
// Seeding carries the RATINGS forward -- the seven-hour half -- while
// advisories are rebuilt from the providers every run.
//
// Both halves of that are load-bearing, and the second is the one that is
// easy to get wrong: an advisory the upstream archive no longer carries
// (withdrawn, D16) must be ABSENT from the rebuilt database. Nothing in
// the build removes a record no provider re-emitted, so a seeded advisory
// is a false positive with no expiry date.
func TestUpdate_SeedCarriesRatingsButNotAdvisories(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "seed.db")
	w, err := store.Create(seed)
	if err != nil {
		t.Fatal(err)
	}
	// This advisory stands in for one upstream has since withdrawn: it is
	// in the seed and this run's provider does not re-emit it.
	if err := w.Put(advisory.Advisory{
		ID: "GHSA-withdrawn-upstream", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "old"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.PutRating(advisory.Rating{CVE: "CVE-2026-OLD", Source: "NVD"}); err != nil {
		t.Fatal(err)
	}
	w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {DataAsOf: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}},
		Ratings:   map[string]store.Provenance{"NVD": {Window: "modified 2026-07-05..2026-08-03"}},
	})
	w.Close()

	// This run fetches ONE advisory and rates ONE new CVE.
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-new", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "new"}},
	}}}
	a := fakeAnnotator{name: "NVD", window: "modified 2026-08-03..2026-08-04",
		ratings: []advisory.Rating{{CVE: "CVE-2026-NEW", Source: "NVD"}}}

	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), dst, seed,
		[]provider.Provider{p}, []provider.Annotator{a}, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	db, err := store.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// The expensive half survived...
	if rs, err := db.RatingsFor("CVE-2026-OLD"); err != nil || len(rs) != 1 {
		t.Errorf("RatingsFor(CVE-2026-OLD) = %v, %v; the seed's rating was lost, which is the whole point of seeding", rs, err)
	}
	// ...alongside this run's.
	if rs, err := db.RatingsFor("CVE-2026-NEW"); err != nil || len(rs) != 1 {
		t.Errorf("RatingsFor(CVE-2026-NEW) = %v, %v; this run's rating is missing", rs, err)
	}
	// ...and this run's advisory is there. Reached through Lookup, which is
	// how advisories are read -- there is no fetch-by-ID on the store, and
	// Lookup is what the matcher itself calls, so this asserts on the path
	// that actually decides findings.
	if got, err := db.Lookup("Go", "new"); err != nil || len(got) != 1 {
		t.Errorf("Lookup(Go, new) = %v, %v; this run's advisory is missing", got, err)
	}
	// But the seed's advisory is GONE, because no provider re-emitted it.
	// If this assertion ever fails, every withdrawn advisory in every seed
	// becomes a permanent false positive.
	if got, err := db.Lookup("Go", "old"); err != nil {
		t.Fatal(err)
	} else if len(got) != 0 {
		t.Errorf("Lookup(Go, old) = %v, want none: a seeded advisory survived a rebuild, so an advisory upstream withdraws can now never be removed", got)
	}
}

// A seeded build must say so. One that printed what a full build prints
// would be the same over-claim this project keeps re-learning (D20, D26).
func TestUpdate_SeededBuildDisclosesWhatItCarriedForward(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "seed.db")
	w, _ := store.Create(seed)
	w.PutRating(advisory.Rating{CVE: "CVE-2026-OLD", Source: "NVD"})
	w.SetMeta(store.Meta{})
	w.Close()

	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), dst, seed, nil, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := errOut.String()
	if !strings.Contains(s, "seeded 1 rating") {
		t.Errorf("stderr does not say how many ratings were carried forward:\n%s", s)
	}
	if !strings.Contains(s, "advisories rebuilt") {
		t.Errorf("stderr does not say advisories were rebuilt rather than inherited:\n%s", s)
	}
}

// A seed that cannot be read fails the build. It must NOT fall back to
// building from empty: the scheduled builder passes --seed every night, so
// one registry outage would publish a one-day database over a complete one
// and every finding outside that day would quietly lose its NVD band. The
// failure has to be loud and the previous artifact has to stay published.
func TestUpdate_AnUnreadableSeedFailsRatherThanBuildingFromEmpty(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	missing := filepath.Join(t.TempDir(), "not-there.db")

	a := fakeAnnotator{name: "NVD", ratings: []advisory.Rating{{CVE: "CVE-2026-NEW", Source: "NVD"}}}

	var out, errOut bytes.Buffer
	code := Update(context.Background(), dst, missing, nil, []provider.Annotator{a}, &out, &errOut)
	if code != 2 {
		t.Errorf("Update with an unreadable seed = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "not-there.db") {
		t.Errorf("stderr does not name the seed it could not read:\n%s", errOut.String())
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("a failed seeded build left a database behind; the next push would publish it")
	}
}

// A seeded build must not present the seed's coverage as this run's. If the
// seed holds 30 days of NVD and this run refreshed one, db status has to
// say so -- otherwise seeding trades a seven-hour build for a database that
// silently over-claims, which is D20's failure in a new place.
func TestUpdate_SeededRunReportsTheWindowItActuallyFetched(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "seed.db")
	w, _ := store.Create(seed)
	w.PutRating(advisory.Rating{CVE: "CVE-2026-OLD", Source: "NVD"})
	w.SetMeta(store.Meta{
		Ratings: map[string]store.Provenance{"NVD": {Window: "modified 2026-07-05..2026-08-03"}},
	})
	w.Close()

	a := fakeAnnotator{name: "NVD", window: "modified 2026-08-03..2026-08-04",
		ratings: []advisory.Rating{{CVE: "CVE-2026-NEW", Source: "NVD"}}}

	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), dst, seed, nil, []provider.Annotator{a}, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	out.Reset()
	if code := Status(dst, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0", code)
	}
	row := ratingSourceLine(t, out.String(), "NVD")
	if !strings.Contains(row, "2026-08-03..2026-08-04") {
		t.Errorf("RATING SOURCE row = %q, want THIS run's window, not the seed's", row)
	}
	// Both CVEs are present, so the count is the merged one -- the window
	// narrowing must not be read as "the older ratings were dropped".
	//
	// Asserted on the split FIELD, not Contains(row, "2"): the row carries
	// "modified 2026-08-03..2026-08-04", and that date contains "2", so a
	// substring check passes with a RECORDS cell of 1, 0, or the words
	// "ran, rated nothing" -- i.e. it survives deleting the seed copy
	// entirely. CLAUDE.md names this shape; it reached this plan anyway.
	fields := strings.Fields(row)
	if len(fields) < 3 || fields[2] != "2" {
		t.Errorf("RATING SOURCE row = %q, want its RECORDS field to be the merged count 2", row)
	}
}
```

- [ ] **Step 2: Run and watch it fail**

Run: `go test ./internal/dbcmd/ -run TestUpdate_Seed`
Expected: FAIL to build — `Update` takes five arguments, not six.

- [ ] **Step 3: Add `Bolt.EachRating`**

In `internal/store/bolt.go`, beside `RatingsFor`:

```go
// EachRating walks every stored rating in key order, which is what a
// seeded build copies forward. Key order is bbolt's own byte order, so
// two runs over the same database visit the same sequence -- this adds no
// nondeterminism to a build (see Meta's own sorted fields for why that
// matters).
func (b *Bolt) EachRating(fn func(advisory.Rating) error) error {
	// (View + bucketRatings cursor + json.Unmarshal + fn, wrapping any
	// decode error with the key the way RatingsFor does)
}
```

Add it to the `Store` interface alongside `RatingsFor`, and to the in-memory fake the matcher tests use.

- [ ] **Step 4: Thread the seed through `Update`**

Change the signature to take `seedPath string` after `dbPath`. The build itself is **unchanged** — `store.Create(tmp)` still makes an empty store and the providers still fill it, which is what keeps a withdrawn advisory absent. The seed is copied in between the providers and the annotators:

```go
// Ratings only, and deliberately so. Advisories are rebuilt from the
// providers above, because nothing here removes a record that no
// provider re-emitted -- a seeded advisory upstream has since withdrawn
// (D16) would be a false positive with no expiry. Ratings have no such
// failure: NVD does not delete CVEs, a revised score changes the
// record's lastModified so the next delta overwrites it, and a rating
// for a CVE no advisory matches is unreachable (Matcher.annotate only
// asks about identifiers a finding already carries).
//
// Copied BEFORE the annotators run, so a delta overwrites the entries it
// re-fetched and leaves the rest.
seeded := 0
if seedPath != "" {
	src, err := store.Open(seedPath)
	if err != nil {
		w.Close()
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: open seed %s: %v\n", seedPath, err)
		return 2
	}
	err = src.EachRating(func(r advisory.Rating) error {
		seeded++
		return w.PutRating(r)
	})
	seedMeta, metaErr := src.Meta()
	src.Close()
	if err != nil {
		w.Close()
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: read seed ratings: %v\n", err)
		return 2
	}
	// The seed's rating provenance is the starting point, so an
	// annotator this run did NOT run keeps the seed's window rather than
	// vanishing from db status. One that DID run overwrites its entry in
	// the loop below -- which is what stops a one-day delta inheriting a
	// thirty-day coverage claim.
	if metaErr == nil {
		maps.Copy(meta.Ratings, seedMeta.Ratings)
	}
	fmt.Fprintf(stderr, "seeded %d rating(s) from %s; advisories rebuilt from source\n", seeded, seedPath)
}
```

- [ ] **Step 5: Update every caller and run the suite**

`cmd/assay/main.go`'s `db build` case passes `""` unless `--seed <ref-or-path>` is given; when given a registry reference, `Pull` it to a temp file first and pass that path. Every existing `Update(...)` call in tests gains a `""`.

Run: `go test ./... && gofmt -l . && go vet ./...`
Expected: PASS, empty gofmt output.

- [ ] **Step 6: Prove the over-claim guard fails**

Change the seed-merge so `meta.Ratings` is copied from the seed *after* the annotator loop rather than before it. Confirm `TestUpdate_SeededRunReportsTheWindowItActuallyFetched` goes RED — this is the mutation that reintroduces the over-claim. Revert and record.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: db build --seed layers onto an existing database

Not a nicety: a full NVD pass is seven hours and a GitHub Actions job is
capped at six, so without seeding the scheduled builder can never produce
a full database at all.

The seed's provenance is the starting point and this run's sources
overwrite their own entries, so a one-day run cannot inherit a thirty-day
coverage claim -- D20's failure would otherwise arrive in a new place, as
a database that quietly reports more freshness than it has."
```

---

### Task 6: The publishing workflow, and the documentation

**Files:**
- Create: `.github/workflows/db-publish.yml`
- Modify: `README.md`, `README.ko.md`
- Modify: `docs/superpowers/specs/2026-07-29-assay-roadmap.md` and `.ko.md` (add D28)
- Modify: `docs/deferred-decisions.md` and `.ko.md` (resolve the OCI entry)

**Interfaces:**
- Consumes: `db build`, `db push`, `db update`, `--seed` from every earlier task.
- Produces: no Go API. This is the slice's user-facing surface.

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/db-publish.yml`:

```yaml
name: publish database

on:
  schedule:
    - cron: "0 6 * * *"
  workflow_dispatch:

permissions:
  contents: read
  packages: write

jobs:
  publish:
    runs-on: ubuntu-latest
    # Comfortably inside the 6h job cap, because this run never does a full
    # NVD pass. It seeds from the published artifact and fetches three days
    # of NVD changes on top -- minutes, not hours. The one full pass is a
    # local bootstrap, run once by a human; see the plan's "Bootstrapping
    # the first artifact".
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26"
      - run: make build
      - name: Log in to ghcr.io
        run: echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u ${{ github.actor }} --password-stdin
      - name: Resolve the artifact reference
        id: ref
        # Read from the binary rather than written literally: the tag is the
        # schema version, and a hardcoded :v6 here would keep publishing to
        # the old tag after a bump, silently serving everyone a database
        # their assay refuses.
        run: echo "ref=$(./bin/assay db ref)" >> "$GITHUB_OUTPUT"
      - name: Build
        env:
          NVD_ENABLE: "1"
          # Three days, not one: a run that fails leaves no gap, because the
          # next day's window still covers what it missed. One day would
          # make every skipped run a permanent hole in the ratings.
          NVD_SINCE_DAYS: "3"
        run: ./bin/assay db build --seed ${{ steps.ref.outputs.ref }}
      - name: Publish
        run: ./bin/assay db push ${{ steps.ref.outputs.ref }}
```

**Note for the implementer:** this needs a small `db ref` subcommand that prints `dbcmd.Ref(dbcmd.DefaultRef)` to stdout and exits 0 — four lines in the `db` switch, and it removes the duplicated schema version. Pin `actions/*` to a commit SHA if the repository's other workflows do.

**Bootstrapping the first artifact.** The daily workflow seeds from an artifact that does not exist yet, so the first one is created by hand, once:

```bash
NVD_ENABLE=1 assay db build          # the full ~7 hours, locally, no job cap
assay db push ghcr.io/kun9497/assay-db:v6
```

Document this in the README as the builder's one-time step. Note that `db build --seed` must fail with a clear error — not silently build from empty — when the reference does not resolve, or the first scheduled run after a registry outage would quietly publish a one-day database over a complete one. Add that to Task 5's tests.

- [ ] **Step 2: Record D28 in the roadmap, bilingually**

Add a `D28` section stating: the database is built centrally and published as an OCI artifact; `db update` pulls and `db build` builds; the schema version is the artifact tag; the artifact's `DataAsOf` is its oldest provider's; a scan still never fetches (D14). Give the reasoning — the measured seven hours, the six-hour job cap that forces seeding, and the choice of ghcr.io because go-containerregistry is already a dependency so OCI costs nothing extra.

- [ ] **Step 3: Resolve the deferred decision, bilingually**

In `docs/deferred-decisions.md` and `.ko.md`, the "Publishing the database as an OCI artifact" entry moves from deferred to done. Follow the existing convention for resolved entries (see the `--fail-on-incomplete` entry, which is struck through in its heading with the resolution written underneath).

- [ ] **Step 4: Update both READMEs**

Mark slice ⑧ done with its checkboxes. Update the Usage section: `assay db update` is now the normal path and takes seconds; `assay db build` is the builder's. State plainly that a scan still makes no network call.

- [ ] **Step 5: Verify the pair**

Run: `gofmt -l . && go vet ./... && go test ./...`
Then confirm every English change has a Korean counterpart in the same commit — `git diff --stat` should show `.md` and `.ko.md` files in matched pairs.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "docs: D28, and the daily publishing workflow

The database is built centrally and published to ghcr.io; db update pulls
it. The schema version is the tag, so a binary only ever asks for
artifacts it can read.

The six-hour job cap against a seven-hour NVD pass is why the daily run
seeds from the previous artifact rather than building from empty, and why
a full build is a manual, chunked exception rather than the schedule."
```

---

## Self-review notes

**Spec coverage.** Every choice the user made is implemented: `db update` pulls and `db build` builds (Task 1, 4); publishing only, no new data sources (nothing in this plan adds a provider); `ghcr.io/kun9497/assay-db` (Task 4's `DefaultRef`, Task 6's workflow).

**The one thing this plan adds beyond the brief**, and why: **Task 5 (seeding)**. It is not scope creep — without it the scheduled builder cannot produce a full database at all, because seven hours does not fit in a six-hour job. Publishing without seeding would ship a pipeline that can never populate the artifact it publishes.

**Known gaps, deliberately out of scope.** No signing or attestation — the pull is digest-verified by go-containerregistry, but nothing proves *who* built it; that is a real gap and belongs in `docs/deferred-decisions.md` rather than here. No `--from file:` air-gapped path; `db build` remains the offline route, and an air-gapped pull wants its own decision about format. No retry or resume on a failed pull.

**Type consistency check.** `dbartifact.Meta` (Task 2) and `store.Meta` (existing) are different types with the same name in different packages — the implementer must not conflate them; `Push` (Task 3) converts between them explicitly. `Update`'s signature changes in Task 5 and every caller in tests must be updated; that is called out in Task 5 Step 5 rather than left to be discovered.
