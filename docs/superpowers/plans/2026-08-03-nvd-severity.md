# NVD severity (D27) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** A finding whose OSV sources all left it unrated can still reach `--fail-on high`,
because NIST scored the CVE and assay now carries that score.

**Architecture:** A second kind of upstream — one that says *what a CVE is worth* rather than
*which package is affected* — enters through a new `provider.Annotator` interface, is stored
in its own bucket keyed by CVE, and is read by the matcher as an additional
`matcher.Rating`. D25 already defines what happens to a rating; nothing about matching,
version comparison or coverage changes.

**Tech Stack:** Go standard library plus the existing `bbolt` store. No new dependencies.

## Global Constraints

Every task's requirements implicitly include these.

- **No new third-party dependencies.** `CGO_ENABLED=0`.
- **A scan never fetches vulnerability data** (D14). NVD is fetched by `assay db update` and
  by nothing else. A scan of an SBOM, a `docker-archive:` tarball or an `oci-dir:` layout must
  still make no network call at all.
- **`unknown` is a band outside the `none < low < medium < high < critical` ordering** (D17),
  never coerced. A source that rated nothing must not pull a rated finding down, and must not
  make a rated one look unrated.
- **Bands are derived from stored CVSS vectors at query time** (D13). Store the vector, never
  a band or a score computed at build time.
- **Version comparison stays per-ecosystem** (D9). **This plan adds no `Comparer` and touches
  none.** NVD supplies no version data we use. If you find yourself comparing versions, stop —
  you are out of scope.
- **Coverage is untouched** (D20). `Covers()` must not report an ecosystem because NVD scores
  exist. A package in an ecosystem this database never ingested must still be reported as
  unevaluated.
- **Exit codes are contract**: `0` clean, `1` findings at/above `--fail-on`, `2` could not run
  or cannot be trusted, precedence `2 > 1 > 0` (D11).
- **Results to stdout, diagnostics to stderr.** `--output json | jq` stays clean.
- **Deterministic, diffable output.** `Ratings` is sorted; map iteration order must never
  reach a caller or the report.
- **Documentation is bilingual**: `README.md` and `README.ko.md` in the same commit; the
  roadmap likewise. Identifiers, flags and paths stay English on both sides.
- **Every test must fail if the behaviour it describes is removed.** After writing one, delete
  or invert the production line it covers, confirm the suite goes red, revert. **Report every
  mutation.** If one survives, investigate whether it is a true equivalent or a real gap and
  say which — on the previous two slices, three of seven survivors were real gaps in this
  plan's own test set.
- **A guard is not covered by the test that mentions it** (CLAUDE.md): a field declared and
  never read by an assertion; a `continue`/`t.Skip` where the subject lives; presence asserted
  where order or count is the point; a format-string prefix satisfying the assertion.
- **Never assert `strings.Contains(a, b)` when another part of the same value contains `b`.**
  CVE ids nest inside advisory ids (`ALPINE-CVE-2025-46394`), and `t.TempDir()` derives its
  path from the test's own name — that has already produced a false pass on this branch.
- `gofmt -l .` empty, `go vet ./...`, `go test ./...` green before every commit.
- Windows dev box: `go test ./...`, **not** `-race` (no C toolchain; CI runs it).

## The measurement this exists to act on

Taken 2026-08-03 against a schema-5 database of 32,046 advisories and NVD's 2.0 API.

| | |
|---|---|
| advisories with no scorable vector | **8,029 (25%)** |
| of those, carrying a CVE | 7,021 |
| of those, carrying **no CVE at all** | **1,008 (13%)** — unreachable, by any design |
| random sample of unrated CVEs queried | 60 |
| NVD carries a CVSS score | **56 (93%)**, 95% CI 84–97% |
| scoring **high or critical** | **29 (48%)**, 95% CI 36–61% |

Concretely, `assay scan ./bin/assay` finds three unrated findings, so `--fail-on low` — the
lowest threshold that exists — exits 0. NVD rates two of them:

```
CVE-2026-39822 (stdlib)  7.8  high
CVE-2026-42505 (stdlib)  5.3  medium
```

The third carries no CVE and stays unknown. That is the 13% arriving in a three-finding scan.

## Fetch shape, measured

`https://services.nvd.nist.gov/rest/json/cves/2.0` paginates. Verified by request:

| | |
|---|---|
| `totalResults` | 372,628 |
| records per request at `resultsPerPage=2000` | 2,000 (4.3 MB, ~33 s) |
| requests for a full sync | **187** |
| wall clock at the no-key rate limit (5 per 30 s → 6.5 s apart) | **~20 minutes** |
| records carrying a CVSS score | 98% |

Per-CVE lookup instead would be ~7,000 requests, about 12 hours. An API key raises the limit
tenfold; it is supported through `NVD_API_KEY` and **never required** — a scanner that only
works for people who registered is a different tool.

## File Structure

| File | Responsibility |
|---|---|
| `internal/provider/provider.go` (modify) | add the `Annotator` interface |
| `internal/provider/nvd/nvd.go` (new) | paginated fetch, rate limiting, optional key |
| `internal/provider/nvd/parse.go` (new) | one NVD record → `advisory.Rating` |
| `internal/store/store.go` (modify) | `Store.RatingsFor(cve)`, `Writer.PutRating`, schema 6 |
| `internal/store/bolt.go` (modify) | the `ratings` bucket |
| `internal/matcher/matcher.go` (modify) | attach NVD ratings by CVE; display rule |
| `internal/dbcmd/dbcmd.go` (modify) | run annotators; `db status` shows them |
| `internal/report/*` (modify) | NVD appears in `--explain` and JSON |
| `README.md`/`.ko.md`, roadmap (modify) | slice ⑦ done, measured numbers |

`internal/version/` is **not** modified. `internal/cataloger/` is **not** modified.

---

### Task 1: The rating, stored

**Files:**
- Modify: `internal/advisory/advisory.go`, `internal/store/store.go`,
  `internal/store/bolt.go`, and their tests

**Interfaces:**
- Produces:
  ```go
  // advisory.Rating is one authority's assessment of one CVE, stored
  // independently of any advisory record.
  type Rating struct {
      CVE      string     // "CVE-2026-39822"
      Source   string     // "NVD"
      Severity []Severity // the same (Type, Score) pairs an Advisory carries
      URL      string     // where a reader can check the claim
  }
  // store
  func (b *Bolt) PutRating(r advisory.Rating) error
  func (b *Bolt) RatingsFor(cve string) ([]advisory.Rating, error)  // sorted by Source
  // SchemaVersion 5 -> 6
  ```

**Why a separate bucket and not a field on `Advisory`.** An advisory is one upstream record
stored losslessly (D13); a rating is a different authority's opinion about a CVE that may
have no advisory of its own, or several. Putting NVD's score on an OSV record would mean
choosing which record to put it on when a CVE has four, and would make the stored OSV data
no longer what OSV said.

**Why the vector and not the band** (D13). Store `Severity` exactly as an advisory does, so
`severity.Highest` derives the band at query time and a scoring bug is a code fix rather than
a database rebuild.

**Why a schema bump.** A schema-5 database has no `ratings` bucket, and reading a missing
bucket would silently return no ratings — a scan that quietly loses every NVD score while
looking healthy. `SchemaVersion = 6` makes an old database refuse through the existing
`ErrSchemaMismatch` path instead.

- [ ] **Step 1: Write the failing tests**

```go
// A rating round-trips, and is keyed on the CVE rather than on any advisory.
func TestPutRating_RoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	want := advisory.Rating{
		CVE:    "CVE-2026-39822",
		Source: "NVD",
		Severity: []advisory.Severity{
			{Type: "CVSS_V31", Score: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
		},
		URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-39822",
	}
	if err := w.PutRating(want); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(Meta{}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.RatingsFor("CVE-2026-39822")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d ratings, want 1", len(got))
	}
	// Asserted field by field, each with its own message: a single DeepEqual
	// reports "not equal" and leaves the reader to diff two structs, and the
	// fields here decide whether a band is derived at all.
	if got[0].CVE != want.CVE {
		t.Errorf("CVE = %q, want %q", got[0].CVE, want.CVE)
	}
	if got[0].Source != want.Source {
		t.Errorf("Source = %q, want %q", got[0].Source, want.Source)
	}
	if len(got[0].Severity) != 1 || got[0].Severity[0].Score != want.Severity[0].Score {
		t.Errorf("Severity = %+v, want the stored vector verbatim (D13)", got[0].Severity)
	}
	if got[0].URL != want.URL {
		t.Errorf("URL = %q, want %q", got[0].URL, want.URL)
	}
}

// A CVE nobody rated returns nothing and no error. "We have no rating" is a
// normal answer, not a failure - the matcher asks this for every finding.
func TestRatingsFor_UnknownCVEIsEmptyNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, _ := Create(path)
	w.SetMeta(Meta{})
	w.Close()
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.RatingsFor("CVE-0000-00000")
	if err != nil {
		t.Fatalf("RatingsFor returned %v; an unrated CVE is a normal answer", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d ratings, want 0", len(got))
	}
}

// Several authorities can rate one CVE. They come back sorted by Source, so
// the report cannot vary between runs.
func TestRatingsFor_SeveralSourcesComeBackSorted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, _ := Create(path)
	// Written in an order that is NOT the sorted one, so the assertion below
	// fails if the sort is dropped rather than passing by luck.
	for _, s := range []string{"NVD", "KISA"} {
		if err := w.PutRating(advisory.Rating{CVE: "CVE-2025-1", Source: s}); err != nil {
			t.Fatal(err)
		}
	}
	w.SetMeta(Meta{})
	w.Close()
	db, _ := Open(path)
	defer db.Close()
	got, err := db.RatingsFor("CVE-2025-1")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range got {
		names = append(names, r.Source)
	}
	if fmt.Sprint(names) != fmt.Sprint([]string{"KISA", "NVD"}) {
		t.Errorf("sources = %v, want [KISA NVD] - sorted, so two runs agree", names)
	}
}

// Schema 6, and a database at any other version refuses rather than serving
// records with no ratings bucket - which would read as "nobody rated any of
// these" on a database that simply predates the field.
func TestSchemaVersionIs6(t *testing.T) {
	if SchemaVersion != 6 {
		t.Errorf("SchemaVersion = %d, want 6", SchemaVersion)
	}
}
```

Extend the existing `TestOpenSchemaMismatch` table (it already covers `SchemaVersion+1` and
`SchemaVersion-1`) — no new test needed there, but confirm both cases still fail on a mutated
comparison.

- [ ] **Step 2: Run them, watch them fail**
- [ ] **Step 3: Implement**

Add `bucketRatings = []byte("ratings")` to `allBuckets`, keyed `"<CVE>\x00<Source>"` so one
CVE can hold several sources and a re-`Put` of the same source replaces rather than
duplicates. Build the key with `keySep`, the existing constant — do **not** type a NUL escape
(CLAUDE.md: a literal `\x00` has flattened into the byte it denotes three times on this repo).

`RatingsFor` uses a bbolt cursor `Seek` over the `"<CVE>\x00"` prefix; sort by `Source`
before returning.

- [ ] **Step 4: Run them, watch them pass**
- [ ] **Step 5: Mutation-check**

| Mutation | Why it matters |
|---|---|
| `RatingsFor` returns an error for an unknown CVE | every unrated finding becomes a scan failure |
| the sort is dropped | non-deterministic report |
| `SchemaVersion` left at 5 | an old database serves zero ratings and looks healthy |
| the ratings bucket is left out of `allBuckets` | `Open` on a fresh database fails, or `Put` panics |
| the key drops the `Source` component | two sources collide and one is lost silently |
| `Severity` is stored as a computed band instead of the vector | D13; a scoring fix would need a rebuild |

- [ ] **Step 6: Commit**

---

### Task 2: The NVD provider

**Files:**
- Create: `internal/provider/nvd/nvd.go`, `internal/provider/nvd/parse.go`, and their tests
- Modify: `internal/provider/provider.go`

**Interfaces:**
- Produces:
  ```go
  // provider.Annotator is an upstream that says what a CVE is worth, rather
  // than which package is affected. NVD is the first; KISA is the reason the
  // interface is not called "NVDProvider".
  type Annotator interface {
      Name() string
      Annotate(ctx context.Context, emit func(advisory.Rating) error) (store.Provenance, error)
  }
  // nvd
  func New(opts Options) *Provider   // Options{APIKey string, BaseURL string}
  ```
- Consumes: `advisory.Rating` from Task 1.

**Why a second interface rather than widening `Provider`.** `Provider.Fetch` emits
`advisory.Advisory` — a statement that a package is affected. NVD makes no such statement, and
D27 turns on it never making one. Widening `Fetch` to emit either kind would put the
distinction in a type switch at every call site; a second interface puts it in the type.

**Rate limiting is part of the contract, not a courtesy.** NVD allows 5 requests per rolling
30 seconds without a key and 50 with one. Space requests at 6.5 s (0.65 s with a key) and do
not parallelise: the limit is per source IP, so concurrency buys nothing and risks a block.

**`BaseURL` exists so the tests never touch the network.** Every test in this task points it
at an `httptest.Server`. There is no test that reaches `services.nvd.nist.gov`.

- [ ] **Step 1: Write the failing tests**

```go
// The pagination contract: keep requesting until startIndex covers
// totalResults, and emit every record along the way.
func TestAnnotate_PaginatesUntilComplete(t *testing.T) {
	var pages int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&pages, 1)
		start := r.URL.Query().Get("startIndex")
		// Three records over two pages, so an implementation that stops after
		// the first page emits 2 and fails the count below.
		switch start {
		case "0":
			io.WriteString(w, `{"totalResults":3,"vulnerabilities":[
			  {"cve":{"id":"CVE-2025-1","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}},
			  {"cve":{"id":"CVE-2025-2","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"}}]}}}]}`)
		default:
			io.WriteString(w, `{"totalResults":3,"vulnerabilities":[
			  {"cve":{"id":"CVE-2025-3","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"}}]}}}]}`)
		}
	}))
	defer srv.Close()

	var got []advisory.Rating
	p := New(Options{BaseURL: srv.URL, PageSize: 2, Pause: 0})
	prov, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("emitted %d ratings, want 3 - a single page is not the whole feed", len(got))
	}
	if atomic.LoadInt32(&pages) != 2 {
		t.Errorf("made %d requests, want 2", pages)
	}
	if prov.Source == "" {
		t.Error("Provenance.Source is empty; a reader cannot check where this came from")
	}
	// D12: freshness is measured from the upstream data, not from now.
	if prov.DataAsOf.IsZero() {
		t.Error("Provenance.DataAsOf is zero - a mirror serving a stale snapshot " +
			"fetched today would report as fresh")
	}
}

// A record with no CVSS metric is skipped, not emitted with an empty vector.
//
// Checked rather than assumed: severity.Highest(nil) already returns unknown,
// so an empty rating would NOT be coerced to none - the band would be right.
// The reason to skip it is different. A rating that says nothing still shows
// up as a source in the Ratings array and in --explain's breakdown, so the
// report would name NVD as having weighed in on 372,628 CVEs it has no
// opinion about. That is noise in the one view built to explain a verdict.
func TestAnnotate_ARecordWithNoScoreIsNotEmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":2,"vulnerabilities":[
		  {"cve":{"id":"CVE-2025-4","metrics":{}}},
		  {"cve":{"id":"CVE-2025-5","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]}`)
	}))
	defer srv.Close()
	var got []advisory.Rating
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: 0})
	if _, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CVE != "CVE-2025-5" {
		t.Fatalf("emitted %+v, want only CVE-2025-5 - an unscored record must not "+
			"arrive as a rating with no vector, which would derive as none, not unknown", got)
	}
}

// v3.1, v4.0, v3.0 and v2 all appear in the feed. Every vector present is
// kept: severity.Highest picks among them at query time (D13), and dropping
// the ones this build does not score yet would bake today's scorer into the
// database.
func TestAnnotate_KeepsEveryVectorVersionPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2025-6","metrics":{
		  "cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
		  "cvssMetricV40":[{"cvssData":{"vectorString":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}],
		  "cvssMetricV2":[{"cvssData":{"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}}]}}}]}`)
	}))
	defer srv.Close()
	var got []advisory.Rating
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: 0})
	if _, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("emitted %d, want 1", len(got))
	}
	if n := len(got[0].Severity); n != 3 {
		t.Errorf("kept %d vectors, want 3 (v3.1, v4.0, v2) - all of them, so the "+
			"band is a query-time decision: %+v", n, got[0].Severity)
	}
}

// An API key is sent as a header when set, and the request is unauthenticated
// when it is not. A provider that silently required a key would work for
// whoever wrote it and for nobody else.
func TestAnnotate_APIKeyIsOptionalAndSentAsAHeader(t *testing.T) {
	for _, tc := range []struct{ name, key, wantHeader string }{
		{"without a key", "", ""},
		{"with a key", "secret-key", "secret-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen string
			var seenOK bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen, seenOK = r.Header.Get("apiKey"), true
				io.WriteString(w, `{"totalResults":0,"vulnerabilities":[]}`)
			}))
			defer srv.Close()
			p := New(Options{BaseURL: srv.URL, APIKey: tc.key, PageSize: 100, Pause: 0})
			if _, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil }); err != nil {
				t.Fatal(err)
			}
			if !seenOK {
				t.Fatal("the server was never called")
			}
			if seen != tc.wantHeader {
				t.Errorf("apiKey header = %q, want %q", seen, tc.wantHeader)
			}
		})
	}
}

// An HTTP error is an error, not an empty feed. Returning nil here would build
// a database with no ratings that looks complete.
func TestAnnotate_AnHTTPErrorIsNotAnEmptyFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: 0})
	_, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err == nil {
		t.Fatal("Annotate returned nil on 503 - a failed sync must not read as " +
			"a feed with nothing in it")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error %q does not carry the status", err)
	}
}

// The context is honoured between pages, so ^C during a 20-minute sync stops
// promptly rather than at the next page boundary twenty minutes later.
func TestAnnotate_RespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":1000000,"vulnerabilities":[{"cve":{"id":"CVE-2025-7","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]}`)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: 0})
	n := 0
	_, err := p.Annotate(ctx, func(advisory.Rating) error {
		n++
		if n == 3 {
			cancel()
		}
		return nil
	})
	if err == nil {
		t.Fatal("Annotate ignored a cancelled context and would have run to a " +
			"million records")
	}
}
```

- [ ] **Step 2: Run them, watch them fail**
- [ ] **Step 3: Implement**

`Options.Pause` defaults to 6.5 s, or 0.65 s when `APIKey` is set; the tests pass 0.
`Options.BaseURL` defaults to the real endpoint. Read `NVD_API_KEY` from the environment in
`cmd/assay`, not here — the provider takes an option, so the tests never depend on the
environment.

`Provenance.DataAsOf` comes from the feed's own `timestamp` field, not `time.Now()` (D12).

- [ ] **Step 4: Run them, watch them pass**
- [ ] **Step 5: Mutation-check**

| Mutation | Must fail |
|---|---|
| stops after the first page | the pagination test |
| a record with no metric is emitted with empty `Severity` | the no-score test — note the band would still be `unknown`, so this is about not naming a source that said nothing, not about a coerced band |
| only `cvssMetricV31` is read | the every-version test |
| the API key is sent when empty, or omitted when set | the key test |
| a non-200 returns `nil` | the HTTP-error test |
| the context is not checked between pages | the cancellation test |
| `DataAsOf` is `time.Now()` | the pagination test's `DataAsOf` assertion — **verify this one actually fails**; if `time.Now()` also satisfies "not zero", the assertion is too weak and needs the feed's own timestamp asserted |

- [ ] **Step 6: Commit**

---

### Task 3: The matcher attaches them

**Do not delegate.** CLAUDE.md reserves `Matcher` and `Evidence` for the main loop, and this
task narrows a D25 rule.

**Files:**
- Modify: `internal/matcher/matcher.go`, `internal/matcher/ratings_test.go`

**The change.** After a finding is built, look up `RatingsFor` on every CVE among its
`Identifiers` and append each result as a `matcher.Rating`. Then narrow the display rule.

**The rule that narrows.** D25 says the finding displays the record that set its band. An NVD
rating can set the band while supplying no `Evidence`, no matched range and no fixed version —
we matched through OSV and asked NIST only for a score. So the finding displays the **matched**
record that set its band; an NVD rating raises the aggregate without ever being displayed
(D27). `beats` is unchanged; what changes is which ratings are candidates for display.

- [ ] **Step 1: Write the failing tests**

```go
// The case D27 exists for: every OSV source left it unrated, NVD did not, and
// the finding is now rated.
func TestMatch_AnNVDRatingRaisesAnOtherwiseUnratedFinding(t *testing.T) {
	s := twoSources(pysecRec(), pysecRec())           // both unrated
	s.ratings = map[string][]advisory.Rating{
		"CVE-2022-28347": {{CVE: "CVE-2022-28347", Source: "NVD",
			Severity: []advisory.Severity{{Type: "CVSS_V31", Score: vecCritical}}}},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[0]
	if f.Severity != severity.Critical {
		t.Errorf("Severity = %v, want critical - NVD rated what no OSV source did", f.Severity)
	}
	var srcs []string
	for _, r := range f.Ratings {
		srcs = append(srcs, r.Database)
	}
	if !slices.Contains(srcs, "NVD") {
		t.Errorf("ratings = %v, want NVD among them", srcs)
	}
}

// ...and it is NOT displayed, because it carries no evidence. The finding
// still shows the record we actually matched against.
func TestMatch_AnNVDRatingIsNeverTheDisplayedRecord(t *testing.T) {
	s := twoSources(pysecRec(), pysecRec())
	s.ratings = map[string][]advisory.Rating{
		"CVE-2022-28347": {{CVE: "CVE-2022-28347", Source: "NVD",
			Severity: []advisory.Severity{{Type: "CVSS_V31", Score: vecCritical}}}},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[0]
	if !strings.HasPrefix(f.Advisory.ID, "PYSEC-") {
		t.Errorf("displayed advisory = %q, want the matched PYSEC record - an NVD "+
			"rating has no Evidence, no matched range and no fixed version, so "+
			"displaying it puts an advisory on screen with nothing behind it",
			f.Advisory.ID)
	}
	if f.Evidence.Fixed == "" {
		t.Error("Evidence was lost - the finding must keep the evidence of the " +
			"record it actually matched")
	}
}

// D17 still holds in both directions: NVD rating nothing must not pull a rated
// finding down, and must not make one look unrated.
func TestMatch_AnAbsentNVDRatingChangesNothing(t *testing.T) {
	withNVD := twoSources(ghsaRec(), pysecRec())
	withNVD.ratings = map[string][]advisory.Rating{"CVE-9999-9999": {{Source: "NVD"}}}
	a, err := New(withNVD).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(twoSources(ghsaRec(), pysecRec())).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(a.Findings) != fmt.Sprint(b.Findings) {
		t.Errorf("a rating for an unrelated CVE changed the finding:\n %v\n %v",
			a.Findings, b.Findings)
	}
}

// A rating is attached once even when several of the finding's identifiers
// resolve to the same CVE, and the store is not asked the same question twice.
func TestMatch_ARatingIsAttachedOnceNotPerIdentifier(t *testing.T) {
	rec := ghsaRec()
	rec.Aliases = []string{"CVE-2022-28347"}
	rec.Upstream = []string{"CVE-2022-28347"} // the same CVE from both fields
	s := fakeStore{byKey: map[string][]advisory.Advisory{key("PyPI", "django"): {rec}}}
	s.ratings = map[string][]advisory.Rating{
		"CVE-2022-28347": {{CVE: "CVE-2022-28347", Source: "NVD",
			Severity: []advisory.Severity{{Type: "CVSS_V31", Score: vecMedium}}}},
	}
	res, err := New(&s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range res.Findings[0].Ratings {
		if r.Database == "NVD" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("NVD appears %d times in Ratings, want 1", n)
	}
	if s.ratingCalls["CVE-2022-28347"] != 1 {
		t.Errorf("the store was asked about one CVE %d times", s.ratingCalls["CVE-2022-28347"])
	}
}
```

`fakeStore` gains `ratings map[string][]advisory.Rating` and `ratingCalls map[string]int`, and
a `RatingsFor` method that records the call. Keep it in-package with the existing helpers.

- [ ] **Step 2-4: fail, implement, pass**
- [ ] **Step 5: Mutation-check**

| Mutation | Must fail |
|---|---|
| NVD ratings are looked up but not appended | the raises test |
| an NVD rating can become the displayed record | the never-displayed test |
| `Evidence` is taken from the NVD rating (i.e. cleared) | the never-displayed test |
| the lookup runs per identifier rather than per distinct CVE | the attached-once test |
| a rating for an unrelated CVE is attached anyway | the absent test |
| the aggregate ignores NVD ratings | the raises test |

- [ ] **Step 6: Commit**

---

### Task 4: Wiring, and saying so

**Files:**
- Modify: `internal/dbcmd/dbcmd.go`, `cmd/assay/main.go`, `internal/report/explain.go`,
  `internal/report/json.go`, and their tests

**The change.** `Update` takes `[]provider.Annotator` alongside `[]provider.Provider` and runs
them after the advisory providers, writing through `PutRating`. `db status` shows the rating
sources and their counts the way it shows `databases:`. `cmd/assay` constructs the NVD
annotator, reading `NVD_API_KEY` from the environment.

**`--explain` already lists every rating** (D25's breakdown), so NVD appears there with no
change beyond the source name being present. **Verify that**, and if the breakdown filters to
matched records, that filter is the bug.

**JSON already emits `ratings`.** Same: verify, do not rebuild.

- [ ] **Step 1: Write the failing test**

```go
// The end-to-end shape of D27, through Run: a finding no OSV source rated
// reaches --fail-on high because NVD rated it.
func TestRun_AnNVDRatingReachesTheGate(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "PYSEC-1", pkg: "unrated", fixed: "2.0.0", aliases: []string{"CVE-2025-9"}},
	})
	// The rating is written into the SAME database, because a scan never
	// fetches anything (D14) - this is what `db update` will have left behind.
	putRating(t, db, advisory.Rating{CVE: "CVE-2025-9", Source: "NVD",
		Severity: []advisory.Severity{{Type: "CVSS_V31", Score: vecCritical}}})
	sbom := buildMatrixSBOM(t, []matrixPkg{{name: "unrated", purlType: "golang"}})

	high := severity.High
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, sbom, Options{FailOn: &high}, &out, &errOut); code != 1 {
		t.Errorf("Run = %d, want 1 - NVD rated this critical, so --fail-on high "+
			"must trip; stdout:\n%s", code, out.String())
	}
	// ...and the source is named, so a reader can see where the band came from.
	if !strings.Contains(out.String(), "NVD") {
		t.Errorf("the report does not name NVD as a source:\n%s", out.String())
	}
}
```

`putRating` is a small helper that opens the built database and writes one rating.

- [ ] **Step 2-4: fail, implement, pass**
- [ ] **Step 5: Mutation-check**

| Mutation | Must fail |
|---|---|
| annotators are constructed but never run | the gate test |
| annotators run before the advisory providers (order swap) | should NOT fail — verify it is a true equivalent and say so, or find the dependency |
| `db status` omits the rating sources | its own test |
| `NVD_API_KEY` is read but not passed through | a `cmd/assay` test |

- [ ] **Step 6: Commit**

---

### Task 5: Against the live feed, and the docs

**Do not delegate.** This checks the plan's own headline claim.

- [ ] **Step 1: Sync NVD into a scratch database**

`ASSAY_DB_DIR=<scratch> assay db update`, with and without `NVD_API_KEY`. Record the wall
clock and the record count against the plan's estimate of 187 requests and ~20 minutes.

- [ ] **Step 2: Re-run the measurement that motivated this**

`assay scan ./bin/assay --fail-on high` must now exit **1**, where it exits 0 today, because
`CVE-2026-39822` is 7.8. Record the before and after. The third finding carries no CVE and
must still be `unknown` — confirm it is, and that the summary still counts it.

- [ ] **Step 3: Re-measure the unrated population**

How many of the 8,029 unrated advisories now carry a band, and how many findings in a real
Django and Alpine scan changed. If the numbers disagree with the plan's sample estimate
(93% scored, 48% high or critical), **the measurement wins** — correct D27 rather than the
measurement, the way D25's fixed-version figure was corrected.

- [ ] **Step 4: Docs, both languages, same commit**

README slice ⑦ checked off with the measured numbers; the roadmap's D27 gains an
after-column. State the sync cost plainly — a `db update` that now takes 20 minutes longer is
a real change to how the tool feels.

- [ ] **Step 5: Commit**

---

## Done when

- A finding every OSV source left unrated reaches `--fail-on high` when NVD rated it high.
- `assay scan ./bin/assay --fail-on high` exits 1, where it exits 0 before this slice.
- An NVD rating never appears as a finding's displayed advisory, and `--explain` lists it.
- A finding whose CVE nobody rated is still `unknown`, still counted, and still trips no
  threshold on its own (D17).
- `assay db update` syncs NVD without an API key, and faster with one.
- A scan makes no network call: `assay scan sbom.cdx.json` on a built database is offline.
- `Covers()` is unchanged — NVD scores do not make an uningested ecosystem look covered.
- A schema-5 database refuses with instructions rather than serving zero ratings.
- Every mutation in every task turns the suite red, or is documented as a true equivalent.

## Not in this plan

CPE matching, or NVD as an independent matching source — D27 records why, with the numbers.
KISA (slice ⑤) uses the same `Annotator` interface and comes next; nothing here should be
NVD-specific that KISA would have to undo. Version data from NVD: it supplies ranges, and we
do not use them — matching stays with OSV and the per-ecosystem `Comparer`s (D9). Storing all
372,628 NVD records: only ratings are kept, and only the fields D13 requires.
