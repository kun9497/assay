# KISA Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A finding matched through OSV picks up KISA's Korean title, summary and advisory link, joined on the CVE — the thing this project was started to build.

**Architecture:** A `knvd` provider fetches KISA's security notices, extracts the CVE IDs each notice names, and writes one enrichment record per CVE into a new `enrichment` bucket. The matcher attaches them to a finding exactly the way NVD ratings attach (D27's `annotate` seam). `db push` strips the bucket before publishing, because the data may not be redistributed (D29).

**Tech Stack:** Go 1.26, stdlib only (`net/http`, `encoding/json`, `regexp`), `go.etcd.io/bbolt` via the existing store.

## Global Constraints

- **Do not add a dependency.** Exactly two direct requires: `go.etcd.io/bbolt`, `github.com/google/go-containerregistry`. Everything here is stdlib. If you think you need a third, report BLOCKED.
- **Exit codes are contract (D11):** `0` clean, `1` findings at or above `--fail-on`, `2` could not run / cannot be trusted. Precedence `2 > 1 > 0`.
- **A scan never fetches vulnerability data (D14).** Enrichment is fetched by `db build`, read by a scan. Nothing added here may be reachable from `internal/scancmd`'s network path.
- **Enrichment never changes a verdict (D3).** It supplies Korean text and a link. It must not affect whether a package matches, what severity a finding has, or any exit code. A scan with an enrichment-free database and one with a full one must produce identical verdicts.
- **Results to stdout, diagnostics to stderr.**
- **Deterministic output** — no map iteration order may reach a caller or a stream.
- **Unknown is a band, not a default (D17).** Enrichment carries no severity at all; do not invent one from KISA's own grading.
- **Coverage is reported, never assumed (D20).** A database without enrichment says so; it does not look like one where no CVE happened to match.
- **Documentation is bilingual.** `X.md` and `X.ko.md` in the same commit, English canonical. Plans are exempt.
- **`-race` does not work here** (no C toolchain); CI runs it. Use `go test -count=1 ./...` — **always with `-count=1`**, because a cached pass has already been reported as green on this branch when it was not.
- `gofmt -l .` empty and `go vet ./...` clean before every commit.

## Verified facts — measured 2026-08-05, do not re-derive

The two blockers recorded against this slice were checked against the live service and **neither exists**:

- **TLS is fine.** `https://knvd.krcert.or.kr/` verifies strictly: `Verify return code: 0 (ok)`, a DigiCert-issued certificate, HTTP 200. The reference crawler's `verify=False` was defensive, not required. Use ordinary TLS; do **not** set `InsecureSkipVerify`.
- **No HTML parsing is needed.** The list response carries `content_text` alongside `content_html` — already plain text, no tags. The reference crawler parses HTML tables only because it builds affected/fixed *version rules*; enrichment (D3) needs none of that.

The endpoint, confirmed by a live call:

```
POST https://knvd.krcert.or.kr/api/core/pu/view/vuln-notice/get
Content-Type: application/json

{"sortBy":"_id","order":-1,"skipCount":0,"limit":50,"preKey":"","nextKey":"",
 "changePerpage":false,"searchOption":"TITLE","content":"","collectionType":"VULNOTICE","tabs":"ko"}
```

Response: `{"resList":[…],"resMsg":…,"resType":…}`. Each element has
`id, idx, title, content, content_html, content_text, url, keywords, attach_files, reservedDate, show_web, view_cnt`.

- `id` is the notice ID; its page is `https://knvd.krcert.or.kr/info/vuln/notice/detail?id={id}`
- `title` is the Korean headline
- `content_text` is plain text and contains the CVE IDs; a probed record yielded `CVE-2026-66066`, another yielded three
- `url` is sometimes an external link and sometimes `null` — it is **not** the notice's own page

Corpus size, measured earlier: **2,039 notices carrying 17,003 distinct CVEs**, of which **413 (2.4%)** are advisories assay already holds — 279 Alpine, 56 Go, 56 npm, 37 PyPI. At 50 per page that is ~41 requests, minutes not hours, which is why enrichment is re-fetched on every build and never seeded.

## D29 — enrichment is built locally and never published

KISA's site is all-rights-reserved with no 공공누리 mark. That does not restrict *scanning* with the data; it restricts **redistributing** it, and `db push` redistributes.

So the enrichment bucket is local-only: `db build` fills it, `db push` strips it, `db update` therefore never delivers it. Anyone who wants Korean text runs a local `db build`.

Two consequences to build in deliberately:

- **The strip must be held by a test.** "We decided not to publish it" is exactly the kind of guarantee that disappears quietly in a later refactor, and here the consequence is a licensing violation rather than a wrong number. Pack an artifact from a database that HAS enrichment, read it back, and assert the bucket is empty.
- **Reversing it must be one change.** When the licence question resolves, including the data should mean deleting the strip — not restructuring where enrichment lives. That is why it goes in the same database rather than a separate file.

## File Structure

| File | Responsibility |
|---|---|
| `internal/advisory/enrichment.go` (new) | The `Enrichment` record: what one CVE gains. |
| `internal/store/store.go`, `bolt.go` (modify) | `bucketEnrichment`, `PutEnrichment`, `EnrichmentFor`, `EachEnrichment`; `SchemaVersion` 6 → 7. |
| `internal/provider/knvd/knvd.go` (new) | The paginated fetch and its `Provenance`. |
| `internal/provider/knvd/parse.go` (new) | One notice → zero or more `Enrichment` records. Pure; no HTTP. |
| `internal/provider/provider.go` (modify) | `Enricher` interface, alongside `Provider` and `Annotator`. |
| `internal/dbcmd/dbcmd.go` (modify) | Run enrichers after annotators; record provenance. |
| `internal/dbcmd/push.go` (modify) | Strip enrichment before packing (D29). |
| `internal/matcher/matcher.go` (modify) | `Finding.Enrichment`, attached in `annotate`. |
| `internal/report/{table,json,explain}.go` (modify) | Render it. |
| `cmd/assay/main.go` (modify) | `KISA_ENABLE`, usage. |

---

### Task 1: The `Enrichment` record and its bucket

**Files:**
- Create: `internal/advisory/enrichment.go`
- Modify: `internal/store/store.go`, `internal/store/bolt.go`
- Test: `internal/store/bolt_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```go
  // package advisory
  type Enrichment struct {
      CVE     string // "CVE-2026-66066"
      Source  string // "KISA"
      Title   string // the Korean headline
      Summary string // the 개요 section, plain text
      URL     string // the notice's own page
  }
  ```
  ```go
  // package store, on Bolt and on the Store interface
  EnrichmentFor(cve string) ([]advisory.Enrichment, error)
  EachEnrichment(fn func(advisory.Enrichment) error) error
  // on Writer
  PutEnrichment(e advisory.Enrichment) error
  ```

- [ ] **Step 1: Write the failing test**

In `internal/store/bolt_test.go`:

```go
// Enrichment is keyed (CVE, Source) exactly as ratings are, so two sources
// can describe one CVE and re-putting one replaces rather than duplicates.
func TestPutEnrichment_RoundTripsAndReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []advisory.Enrichment{
		{CVE: "CVE-2026-1", Source: "KISA", Title: "첫 번째", Summary: "요약", URL: "https://example.test/1"},
		{CVE: "CVE-2026-1", Source: "KISA", Title: "고쳐 쓴 제목", Summary: "요약", URL: "https://example.test/1"},
		{CVE: "CVE-2026-10", Source: "KISA", Title: "이웃", Summary: "요약", URL: "https://example.test/10"},
	} {
		if err := w.PutEnrichment(e); err != nil {
			t.Fatal(err)
		}
	}
	w.SetMeta(Meta{})
	w.Close()

	db, _ := Open(path)
	defer db.Close()

	got, err := db.EnrichmentFor("CVE-2026-1")
	if err != nil {
		t.Fatal(err)
	}
	// One record, the second Put having replaced the first. Asserted on the
	// title, because the CVE and Source are what the key is made of and
	// would match either way.
	if len(got) != 1 || got[0].Title != "고쳐 쓴 제목" {
		t.Errorf("EnrichmentFor(CVE-2026-1) = %+v, want exactly the replaced record", got)
	}
	// CVE-2026-1 is a byte prefix of CVE-2026-10. The same trap RatingsFor
	// has: without the separator in the seek prefix, or without the
	// HasPrefix bound, the neighbour bleeds in.
	if got[0].URL != "https://example.test/1" {
		t.Errorf("EnrichmentFor(CVE-2026-1) returned the neighbour: %+v", got)
	}
	if got, err := db.EnrichmentFor("CVE-2026-10"); err != nil {
		t.Fatal(err)
	} else if len(got) != 1 || got[0].Title != "이웃" {
		t.Errorf("EnrichmentFor(CVE-2026-10) = %+v, want its own record", got)
	}
}

// An unenriched CVE is a normal answer, not a failure: the matcher asks for
// every finding and most CVEs have no Korean notice.
func TestEnrichmentFor_UnknownCVEIsEmptyNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, _ := Create(path)
	w.SetMeta(Meta{})
	w.Close()
	db, _ := Open(path)
	defer db.Close()
	got, err := db.EnrichmentFor("CVE-2026-999")
	if err != nil {
		t.Fatalf("EnrichmentFor returned an error for an unenriched CVE: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("EnrichmentFor = %+v, want empty", got)
	}
}

// Schema 7. A v6 database must be refused rather than read as one where
// nothing happened to be enriched.
func TestSchemaVersionIs7(t *testing.T) {
	if SchemaVersion != 7 {
		t.Errorf("SchemaVersion = %d, want 7", SchemaVersion)
	}
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `go test -count=1 ./internal/store/`
Expected: build failure — `PutEnrichment` and `EnrichmentFor` are undefined.

- [ ] **Step 3: Implement**

Create `internal/advisory/enrichment.go`:

```go
package advisory

// Enrichment is what one authority says about a CVE in prose, for a reader.
//
// It is deliberately not an Advisory and not a Rating. An Advisory says a
// package is affected and can produce a finding; a Rating says how bad a CVE
// is and can raise a band. Enrichment does neither — it carries a title, a
// summary and a link, and D3 fixes it that way: KISA describes much of its
// corpus in prose with no ecosystem and no package name, so treating it as a
// matching source would invent findings nothing can substantiate.
//
// Nothing here may reach a verdict. A scan against a database with no
// enrichment and one with a full bucket must agree on every exit code.
type Enrichment struct {
	CVE    string
	Source string
	Title  string
	// Summary is the notice's own overview section, plain text. It is
	// display copy, not something to parse: the store keeps what upstream
	// wrote (D13) and any structure a reader needs is derived at render
	// time.
	Summary string
	URL     string
}
```

In `internal/store/bolt.go`, beside `bucketRatings`:

```go
bucketEnrichment = []byte("enrichment") // "<CVE>\x00<Source>" -> the Enrichment record, once
```

Add it to whatever `Create` uses to make buckets and to whatever `Open` verifies. Then, mirroring `PutRating`/`RatingsFor`/`EachRating` exactly — including the `cve + keySep` seek prefix and the `bytes.HasPrefix` bound, which exist because one CVE ID is a byte prefix of another — add `PutEnrichment`, `EnrichmentFor` and `EachEnrichment`. Sort `EnrichmentFor`'s result by `Source` for the same reason `RatingsFor` does: two runs against one database must agree.

Bump `SchemaVersion` to 7 in `internal/store/store.go`. Add the three methods to the `Store` interface and `PutEnrichment` to `Writer`, then fix every fake that implements them (`internal/matcher/matcher_test.go`'s `fakeStore` at minimum — the build will name the rest).

- [ ] **Step 4: Run the tests**

Run: `go test -count=1 ./internal/store/ ./internal/matcher/`
Expected: PASS.

- [ ] **Step 5: Prove the prefix guard is held**

Apply each mutation, confirm RED, revert, and record the diff and result:
1. `prefix := []byte(cve + keySep)` → `prefix := []byte(cve)`
2. drop `bytes.HasPrefix(k, prefix)` from the loop condition
3. drop the sort from `EnrichmentFor`

If mutation 3 survives, say so — the sort may be redundant against bbolt's key order today, exactly as it is in `RatingsFor`, and that is a documented equivalent rather than a gap.

- [ ] **Step 6: Commit**

```bash
git add internal/advisory/enrichment.go internal/store/
git commit -m "feat(store): an enrichment bucket, keyed like ratings (schema 7)

Enrichment is prose about a CVE for a reader: a title, a summary and a
link. It is neither an Advisory nor a Rating, and D3 fixes it that way --
KISA describes much of its corpus with no ecosystem and no package name, so
treating it as a matching source would invent findings nothing can
substantiate.

Keyed (CVE, Source) exactly as ratings are, including the separator in the
seek prefix and the HasPrefix bound: CVE-2026-1 is a byte prefix of
CVE-2026-10, and both guards were unheld in RatingsFor until a test went
looking."
```

---

### Task 2: Parsing one notice into enrichment records

**Files:**
- Create: `internal/provider/knvd/parse.go`
- Test: `internal/provider/knvd/parse_test.go`

**Interfaces:**
- Consumes: `advisory.Enrichment` (Task 1).
- Produces:
  ```go
  const SourceName = "KISA"
  const detailURL = "https://knvd.krcert.or.kr/info/vuln/notice/detail?id="

  type rawNotice struct {
      ID          string `json:"id"`
      Title       string `json:"title"`
      ContentText string `json:"content_text"`
  }

  func convert(n rawNotice) []advisory.Enrichment
  ```

**Design notes:** this task is pure — no HTTP, no store. One notice names zero or more CVEs, and each named CVE gets a record pointing back at the same notice. A notice naming no CVE produces nothing: enrichment is a CVE join, and a record with no key is unreachable.

**Do not parse `content_html`.** `content_text` is already plain text. The reference crawler's HTML table parsing exists to build version rules, which D3 says this is not.

- [ ] **Step 1: Write the failing test**

Create `internal/provider/knvd/parse_test.go`:

```go
package knvd

import (
	"strings"
	"testing"
)

// One notice, several CVEs: each gets its own record pointing back at the
// same notice, because the join is on the CVE and a reader following any of
// them wants the same page.
func TestConvert_OneRecordPerNamedCVE(t *testing.T) {
	got := convert(rawNotice{
		ID:    "6a7164a72677c331e44a17f8",
		Title: "Rails 제품 보안 업데이트 권고",
		ContentText: "□ 개요 o Rails에서 발생하는 취약점을 해결한 보안 업데이트 발표 " +
			"□ 설명 o Insecure Default Initialization 취약점(CVE-2026-66066) " +
			"o 두 번째 취약점(CVE-2026-70001)",
	})
	if len(got) != 2 {
		t.Fatalf("convert produced %d record(s), want one per CVE: %+v", len(got), got)
	}
	seen := map[string]bool{}
	for _, e := range got {
		seen[e.CVE] = true
		if e.Source != SourceName {
			t.Errorf("Source = %q, want %q", e.Source, SourceName)
		}
		if e.Title != "Rails 제품 보안 업데이트 권고" {
			t.Errorf("Title = %q, want the notice's own headline", e.Title)
		}
		// The link must be the notice's page, built from its id. The list
		// response's own `url` field is an external reference and is often
		// null, so it is not what a reader should be sent to.
		if want := detailURL + "6a7164a72677c331e44a17f8"; e.URL != want {
			t.Errorf("URL = %q, want %q", e.URL, want)
		}
	}
	for _, want := range []string{"CVE-2026-66066", "CVE-2026-70001"} {
		if !seen[want] {
			t.Errorf("%s missing from %+v", want, got)
		}
	}
}

// The same CVE named twice in one notice yields one record, not two. The
// store would collapse them anyway, but emitting duplicates makes the
// provenance count lie about how much was written.
func TestConvert_DeduplicatesWithinANotice(t *testing.T) {
	got := convert(rawNotice{
		ID:          "abc",
		Title:       "제목",
		ContentText: "CVE-2026-1 설명 CVE-2026-1 다시 CVE-2026-1",
	})
	if len(got) != 1 {
		t.Errorf("convert produced %d record(s), want 1: %+v", len(got), got)
	}
}

// A notice naming no CVE produces nothing. Enrichment is a CVE join, so a
// record with no key could never be read back.
func TestConvert_ANoticeWithNoCVEProducesNothing(t *testing.T) {
	if got := convert(rawNotice{ID: "abc", Title: "제목", ContentText: "CVE 없는 안내문"}); len(got) != 0 {
		t.Errorf("convert produced %+v, want nothing", got)
	}
}

// The summary is the overview section when there is one, so a reader gets
// the point rather than the whole notice. KISA marks it "□ 개요" and ends it
// at the next "□ " heading.
func TestConvert_SummaryIsTheOverviewSection(t *testing.T) {
	got := convert(rawNotice{
		ID:    "abc",
		Title: "제목",
		ContentText: "□ 개요 o 업데이트 발표 " +
			"□ 설명 o 자세한 내용 CVE-2026-1 " +
			"□ 해결 방안 o 최신 버전으로 갱신",
	})
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	if !strings.Contains(got[0].Summary, "업데이트 발표") {
		t.Errorf("Summary = %q, want the 개요 section", got[0].Summary)
	}
	if strings.Contains(got[0].Summary, "최신 버전으로 갱신") {
		t.Errorf("Summary = %q, want it to stop at the next heading", got[0].Summary)
	}
}

// A notice with no 개요 heading still yields a usable summary rather than an
// empty one -- the corpus is not uniform, and an empty field renders as a
// finding that gained nothing.
func TestConvert_FallsBackWhenThereIsNoOverviewHeading(t *testing.T) {
	got := convert(rawNotice{ID: "abc", Title: "제목", ContentText: "CVE-2026-1 에 대한 안내입니다"})
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	if got[0].Summary == "" {
		t.Error("Summary is empty for a notice with no 개요 heading")
	}
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `go test -count=1 ./internal/provider/knvd/`
Expected: build failure — the package does not exist.

- [ ] **Step 3: Implement**

Create `internal/provider/knvd/parse.go` with `SourceName`, `detailURL`, `rawNotice`, and `convert`. Requirements the tests above pin:

- CVE IDs come from `regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)` over `ContentText`, matched case-insensitively and **normalised to upper case** before use, because the store key is exact and `cve-2026-1` must not become a second record.
- Deduplicate within a notice, and emit in **sorted order** so a run is reproducible (D: no map iteration order may reach a caller).
- `URL` is `detailURL + n.ID`. Do not use the response's `url` field.
- `Summary` is the text between `□ 개요` and the next `□ ` heading, whitespace-collapsed; when there is no such heading, fall back to the whole `ContentText`, whitespace-collapsed and truncated to a sensible display length.

- [ ] **Step 4: Run the tests**

Run: `go test -count=1 ./internal/provider/knvd/ -v`
Expected: all five PASS.

- [ ] **Step 5: Prove the tests can fail**

Apply, confirm RED, revert, record each:
1. drop the upper-casing of matched CVE IDs, and add a lower-case `cve-2026-1` to the dedup test's input
2. `URL: detailURL + n.ID` → `URL: n.URL` (add the field to `rawNotice` for the mutation, then revert both)
3. return the whole `ContentText` as `Summary` unconditionally
4. drop the dedup

- [ ] **Step 6: Commit**

```bash
git add internal/provider/knvd/
git commit -m "feat(knvd): one notice becomes one enrichment record per CVE

Pure: no HTTP, no store. content_text is already plain text -- checked
against the live service 2026-08-05 -- so nothing here parses HTML. The
reference crawler does, but only to build affected/fixed version rules,
which D3 says enrichment is not.

The link is built from the notice id, not the response's own url field:
that one is an external reference and is frequently null."
```

---

### Task 3: The KNVD provider

**Files:**
- Create: `internal/provider/knvd/knvd.go`
- Modify: `internal/provider/provider.go`
- Test: `internal/provider/knvd/knvd_test.go`

**Interfaces:**
- Consumes: `convert` (Task 2), `store.Provenance`.
- Produces:
  ```go
  // package provider
  type Enricher interface {
      Name() string
      Enrich(ctx context.Context, emit func(advisory.Enrichment) error) (store.Provenance, error)
  }

  // package knvd
  type Options struct {
      BaseURL  string
      PageSize int
      Pause    *time.Duration
      Progress io.Writer
  }
  func New(opts Options) *Provider
  ```

**Design notes.** Model this on `internal/provider/nvd`, which solved the same problems the hard way today; read it before writing. Specifically:

- **Pagination progress guard.** A page returning zero records while `skipCount` has not reached the total must be an error, not an infinite loop.
- **Retry on anything not definitely permanent.** Reuse nvd's policy: retry everything except a cancelled/expired context and a 4xx other than 429. Enumerating transient cases only ever covers the one already seen — nvd's first version matched HTTP statuses only and then died on a transport error.
- **Progress on stderr**, per page, with counts. A sync that prints nothing is indistinguishable from one that has hung.
- **Ordinary TLS.** Do not set `InsecureSkipVerify`; verified working 2026-08-05.
- `Provenance.Records` counts records emitted; `DataAsOf` is the fetch time — KISA's list gives no upstream timestamp this provider can trust, so say so in a comment rather than inventing one.

- [ ] **Step 1: Write the failing test**

Create `internal/provider/knvd/knvd_test.go`. Every test serves the list JSON from `httptest.NewServer`; none touches the live service.

```go
// Pages until the corpus is covered, emitting one record per named CVE.
func TestEnrich_PagesThroughTheCorpus(t *testing.T) { /* two pages of one notice each, assert both CVEs emitted and two requests made */ }

// A zero-record page short of the total is refused rather than retried
// forever: nothing else advances skipCount, so it is the one response shape
// that cannot make progress.
func TestEnrich_RefusesAPageThatCannotMakeProgress(t *testing.T) { /* ... */ }

// A transient failure is retried; a permanent one is not.
func TestEnrich_RetriesTransientFailures(t *testing.T) { /* 503 twice then success */ }
func TestEnrich_DoesNotRetryAPermanentFailure(t *testing.T) { /* 404, exactly one request */ }

// Progress is reported per page with counts, so a stalled sync is
// distinguishable from a slow one.
func TestEnrich_ReportsProgress(t *testing.T) { /* ... */ }
```

Write these out in full, following `internal/provider/nvd/nvd_test.go`'s existing shapes — including its `TestMain` that zeroes the retry schedule while keeping its length, and a test that the shipped schedule really waits. Do not copy nvd's mistake of asserting elapsed wall clock.

- [ ] **Step 2: Run and watch it fail**

Run: `go test -count=1 ./internal/provider/knvd/`
Expected: build failure — `New` and `Enrich` are undefined.

- [ ] **Step 3: Implement**

Add the `Enricher` interface to `internal/provider/provider.go` beside `Provider` and `Annotator`, with a `var _ provider.Enricher = (*Provider)(nil)` assertion inside `knvd` so a signature drift fails that package's own build.

Implement the POST body exactly as recorded in the plan header, with `skipCount` advancing by the number of records actually returned — never by the requested page size, which the last page will not honour.

- [ ] **Step 4: Run the tests**

Run: `go test -count=1 ./internal/provider/knvd/ -v && gofmt -l . && go vet ./...`

- [ ] **Step 5: Prove the guards are held**

Mutations, each applied / RED / reverted / recorded:
1. remove the zero-page progress guard
2. advance `skipCount` by the requested page size instead of the returned count
3. make `retryable` match HTTP statuses only
4. send `InsecureSkipVerify: true` — this one should not be caught by a test, and that is the point: note in the report that TLS strictness is not test-enforceable here and is held by review instead

- [ ] **Step 6: Commit**

```bash
git add internal/provider/knvd/ internal/provider/provider.go
git commit -m "feat(knvd): paginated fetch of KISA security notices

Modelled on internal/provider/nvd, which paid for these lessons today: a
zero-record page short of the total is the one shape that cannot advance, a
retry allow-list only ever covers the failure already seen, and a sync that
prints nothing cannot be told from one that has hung.

Ordinary TLS. The reference crawler disables verification; checked against
the live service 2026-08-05, it verifies strictly and does not need to."
```

---

### Task 4: Build wiring, and the D29 strip

**Files:**
- Modify: `internal/dbcmd/dbcmd.go`, `internal/dbcmd/push.go`, `cmd/assay/main.go`
- Test: `internal/dbcmd/dbcmd_test.go`, `internal/dbcmd/push_guard_test.go`

**Interfaces:**
- Consumes: `provider.Enricher` (Task 3), `store.PutEnrichment` (Task 1).
- Produces: `Update(ctx, dbPath, seedPath, seedRef string, providers []provider.Provider, annotators []provider.Annotator, enrichers []provider.Enricher, stdout, stderr io.Writer) int`.

**This task carries D29.** `db push` must publish an artifact with an empty enrichment bucket, whatever the local database holds.

- [ ] **Step 1: Write the failing tests**

In `internal/dbcmd/push_guard_test.go`:

```go
// D29: enrichment is built locally and never published. KISA's site is
// all-rights-reserved with no 공공누리 mark, which does not restrict scanning
// with the data but does restrict redistributing it -- and db push
// redistributes.
//
// Asserted by reading the artifact back, not by inspecting what Push was
// handed: the guarantee is about what leaves the machine.
func TestPush_NeverPublishesEnrichment(t *testing.T) {
	// build a database WITH enrichment, push it, pull the artifact into a
	// fresh path, and assert EnrichmentFor returns nothing while the
	// advisories and ratings survive
}
```

In `internal/dbcmd/dbcmd_test.go`:

```go
// Enrichers run and their records land.
func TestUpdate_RunsEnrichers(t *testing.T) { /* ... */ }

// A failing enricher does NOT fail the build, unlike a provider or an
// annotator. Enrichment cannot change a verdict (D3), so losing it costs a
// reader some Korean text and costs the scan nothing -- while failing the
// build would mean an unreachable KISA endpoint stops a user getting any
// database at all. It is reported on stderr and in db status, never
// silently dropped (D20).
func TestUpdate_AFailingEnricherIsReportedButDoesNotFailTheBuild(t *testing.T) { /* ... */ }
```

- [ ] **Step 2: Run and watch them fail**

Run: `go test -count=1 ./internal/dbcmd/`

- [ ] **Step 3: Implement**

- `Update` gains `enrichers []provider.Enricher`, run after the annotators. A failing enricher prints `warning: enricher %s: %v` to stderr and records nothing for that source; it does not abort. Every existing caller gains `nil`.
- Record each enricher's provenance in a new `Meta.Enrichment map[string]Provenance`, with counts derived from the bucket in `SetMeta`, exactly as `RatingCounts` is — self-report has already over-claimed once on this branch.
- `db status` gains an ENRICHMENT SOURCE table beside RATING SOURCE, following its conventions including the "ran, enriched nothing" wording.
- `push.go` strips the bucket. Copy the database to the temp path it already packs from and delete the enrichment bucket there, so the live database keeps its data. Say in a comment that removing this is how D29 is reversed once the licence question resolves.
- `cmd/assay/main.go`: `KISA_ENABLE` gates the enricher exactly as `NVD_ENABLE` gates the annotator, with a `newKNVDEnricher` package var as the test seam. Document it in `usage`.

- [ ] **Step 4: Run everything**

Run: `go test -count=1 ./... && gofmt -l . && go vet ./...`

- [ ] **Step 5: Prove the strip is held**

1. Delete the strip in `push.go`. `TestPush_NeverPublishesEnrichment` must go RED. **If it does not, the D29 guarantee is unheld and the task is not done.**
2. Make a failing enricher abort the build. The build-does-not-fail test must go RED.
3. Derive the enrichment counts from self-report instead of the bucket. A count test must go RED.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: build enrichment locally, strip it before publishing (D29)

KISA's site is all-rights-reserved with no 공공누리 mark. That does not
restrict scanning with the data; it restricts redistributing it, and db
push redistributes. So db build fills the bucket, db push strips it, and
db update never delivers it.

A test reads the artifact back and asserts the bucket is empty. \"We decided
not to publish it\" is exactly the guarantee that disappears in a later
refactor, and here the consequence is a licensing violation rather than a
wrong number.

A failing enricher warns rather than aborting, unlike a provider or an
annotator: enrichment cannot change a verdict (D3), so losing it costs a
reader some Korean text -- while failing the build would let an unreachable
KISA endpoint stop a user getting any database at all."
```

---

### Task 5: Attaching enrichment to a finding, and rendering it

**Files:**
- Modify: `internal/matcher/matcher.go`, `internal/report/{table,json,explain}.go`
- Test: `internal/matcher/matcher_test.go`, `internal/report/*_test.go`

**Interfaces:**
- Consumes: `store.EnrichmentFor` (Task 1).
- Produces: `Finding.Enrichment []Enrichment`, where

  ```go
  type Enrichment struct {
      Source  string
      Title   string
      Summary string
      URL     string
  }
  ```

**Design notes.** Attach it in `Matcher.annotate`, in the same loop that already asks `RatingsFor` for each `CVE-`-prefixed identifier. Sort by `Source` so two runs agree.

**The property to hold hardest:** enrichment must not change a verdict (D3). Whatever it adds, `Finding.Severity`, `Finding.Score`, the summary counts and every exit code must be identical to a scan against a database with no enrichment at all.

- [ ] **Step 1: Write the failing test**

```go
// Enrichment attaches on the CVE, exactly as ratings do.
func TestMatch_AttachesEnrichmentByCVE(t *testing.T) { /* ... */ }

// ...and changes no verdict (D3). The same target matched against a store
// with enrichment and one without must agree on severity, on the summary
// counts and on the exit code -- enrichment is prose for a reader, and a
// reader's convenience must never move a gate.
func TestMatch_EnrichmentChangesNoVerdict(t *testing.T) {
	// run Match twice against fakes differing ONLY in enrichment, and
	// compare the results with Enrichment zeroed out on both sides
}
```

Then, in `internal/report`: the table shows a marker and a footnote naming the source; `--explain` prints the title, summary and URL in full; JSON carries it under a new key. The JSON golden file changes, and `schemaVersion` must be bumped — the shape changed, and this is the third time that constant's doc comment has been tested by an addition.

- [ ] **Step 2: Run and watch fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run everything**

Run: `go test -count=1 ./... && gofmt -l . && go vet ./...`

- [ ] **Step 5: Prove the verdict-independence holds**

1. Make `annotate` raise `Finding.Severity` when enrichment is present. `TestMatch_EnrichmentChangesNoVerdict` must go RED.
2. Drop the sort on enrichment. A determinism assertion must go RED, or record it as an equivalent with the reason.
3. Delete the `--explain` rendering. A report test must go RED — not one that passes because the CVE ID appears elsewhere in the output.

- [ ] **Step 6: Commit**

---

### Task 6: D29 in the roadmap, and the documentation

**Files:**
- Modify: `docs/superpowers/specs/2026-07-29-assay-roadmap.md` + `.ko.md`
- Modify: `docs/deferred-decisions.md` + `.ko.md`
- Modify: `README.md` + `.ko.md`

- [ ] **Step 1: Record D29 bilingually**

The decision: enrichment is built locally and stripped before publishing, because KISA's terms restrict redistribution and `db push` redistributes. Include the reasoning, the revisit trigger (the licence question resolving), and the fact that reversing it is deleting the strip.

- [ ] **Step 2: Correct the record on the two blockers**

Both `README` files and the roadmap currently say this slice is blocked on TLS and on HTML table parsing. Neither is true, and the way that was found — calling the service instead of reading about it — is worth stating once. Measured 2026-08-05: strict TLS verifies, and `content_text` arrives already plain.

- [ ] **Step 3: Mark slice ⑤ done, bilingually**

- [ ] **Step 4: Update `docs/deferred-decisions.md` + `.ko.md`**

"Splitting KISA data into a separate artifact" now has a concrete trigger — it is what happens if the licence resolves and the data becomes publishable but too large to bundle. Update it to say so.

- [ ] **Step 5: Verify the pair**

`git diff --stat` must show `.md` and `.ko.md` files in matched pairs, all in one commit.

- [ ] **Step 6: Commit**

---

## Self-review notes

**Spec coverage.** Every piece of the slice has a task: the record and bucket (1), parsing (2), fetching (3), build wiring plus the D29 strip (4), matcher and reports (5), documentation (6).

**What this plan deliberately does not do.** No affected/fixed version extraction — that is a matching concern and D3 says enrichment is not matching. No seeding of enrichment, because a full fetch is ~41 requests. No KISA severity, because D17 forbids inventing a band and KISA's grading does not map onto CVSS.

**The one thing most likely to go wrong** is Task 4's strip. It is the only place where a silent failure has a licensing consequence rather than a correctness one, and it is the only guarantee in this plan that cannot be inferred from behaviour a user would notice. Its mutation is not optional.

**Known risk, stated rather than hidden.** The corpus overlap is 2.4% — roughly one Alpine finding in sixteen gains Korean text. This is a modest feature by design, and the plan should not be judged against a larger one.
