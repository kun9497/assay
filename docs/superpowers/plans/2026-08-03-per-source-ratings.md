# Per-source ratings (D25) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A finding reports what every source said about it, and the verdict stops depending
on which record the index happened to list first.

**Architecture:** The advisory gains an explicit authoring-database field written at ingest
(schema 5). The matcher stops discarding the records it currently drops and attaches them to
the finding as ratings. The gate takes the highest band across those ratings. The renderers
show them.

**Tech Stack:** Go standard library plus the existing `bbolt` store. No new dependencies.

## Global Constraints

- No new third-party dependencies. `CGO_ENABLED=0`.
- Exit codes are contract: `0` clean, `1` findings at or above `--fail-on`, `2` could not run
  or cannot be trusted, precedence `2 > 1 > 0` (D11).
- Unrated severity is a band, not a default (D17). `unknown` sits outside the ordering, never
  below `none`. A source that rated nothing must not pull a rated finding down.
- Bands are derived from the stored CVSS vector at query time (D13), never baked in.
- Version comparison stays per-ecosystem (D9). Nothing in this plan touches a `Comparer`.
- `Components == Cataloged + every skip counter` still holds in every cataloger.
- Results to stdout, diagnostics to stderr. `--output json | jq` stays clean.
- Deterministic, diffable output (goal #3). Ratings must be **sorted**, not left in map or
  index order — the whole point of this change is to stop depending on incidental ordering.
- Every test must fail if the behaviour it describes is removed. After writing one, delete or
  invert the production line it covers and confirm the suite goes red. Report the mutations.
- **A guard is not covered by the test that mentions it** (CLAUDE.md). Watch for a field
  declared and never read, a `continue`/`t.Skip` where the subject lives, presence asserted
  where order is the point, and a format-string prefix satisfying the assertion.
- **Never assert `strings.Contains` when another field of the same output contains the value.**
  Band names are short words and advisory IDs nest.
- Documentation is bilingual: `README.md` and `README.ko.md` change in the same commit.
- `gofmt -l .` empty, `go vet ./...`, `go test ./...` green before every commit.

## Measured inputs

Measured on the live database (32,101 advisories, data as of 2026-07-31), over the packages a
real scan touches.

| Question | Answer |
|---|---|
| vulnerability groups keyed by CVE | **440** |
| with more than one record | **169 (38%)** |
| of those, severity differs | **140** |
| of those, the fixed version differs | **152** |
| namespace combinations seen | `GHSA+PYSEC` 161, `GHSA+GO` 4, `GHSA` alone 4 |
| id namespaces present | `ALPINE`, `GHSA`, `GO`, `PYSEC` |

Concrete disagreements, from the live database:

```
django  CVE-2022-28347   GHSA-w24h-v9qh-8gxj critical   PYSEC-2022-191 unknown
django  CVE-2018-6188    GHSA-rf4j-j272-fj86 high       PYSEC-2018-4   unknown
django  CVE-2016-2048    GHSA-46x4-9jmv-jc8p high       PYSEC-2016-14  unknown
docker/cli CVE-2021-41092 GHSA-… medium  GO-… unknown   fixed 20.10.9 vs 20.10.9+incompatible
```

Today's behaviour, measured: `assay scan django-3.2.12.cdx.json` reports 19 findings as
critical 5 / high 10 / medium 4, and `--fail-on critical` exits 1. That is correct **by
luck** — `internal/store/bolt.go`'s `appendID` builds the package index with
`ids = append(ids, id)` and never sorts, so the winner is the provider's archive walk order,
and GHSA happens to come first.

---

## File structure

| File | Responsibility |
|---|---|
| `internal/advisory/advisory.go` | `Advisory.Database` — the authoring database, explicit |
| `internal/provider/osv/record.go` | set it at ingest from the record's identifier |
| `internal/store/store.go` | `SchemaVersion` 4 → 5 |
| `internal/matcher/matcher.go` | keep the records dedup drops; `Finding.Ratings` |
| `internal/severity/severity.go` | nothing — `Highest` already does the within-record rule |
| `internal/scancmd/scancmd.go` | the gate reads the aggregate band |
| `internal/report/{table,json,explain}.go` | show the ratings |
| `README.md`, `README.ko.md` | what a multi-source finding looks like |

---

### Task 1: The authoring database, stored explicitly

**Files:**
- Modify: `internal/advisory/advisory.go`, `internal/provider/osv/record.go`,
  `internal/store/store.go`, and their tests

**Interfaces:**
- Produces: `Advisory.Database string` — `"GHSA"`, `"PYSEC"`, `"GO"`, `"ALPINE"`, … and
  `SchemaVersion = 5`.

**Why a field and not a prefix.** The authoring database is inferable from the identifier
today (`GHSA-…`, `PYSEC-…`), but a prefix is a naming convention, not data. Deriving it at
query time puts a parser in the read path that silently returns the wrong answer for any
identifier shape nobody anticipated — and `ALPINE-CVE-2025-46394` already shows that these
identifiers nest. Deriving it once, at ingest, from the record the provider is holding, means
a wrong answer is a wrong stored value that a test can pin.

**Why a schema bump.** A database built before this field has it empty everywhere, and an
empty `Database` would render as a rating from a source with no name. `SchemaVersion = 5`
makes an old database refuse with instructions (the existing `ErrSchemaMismatch` path)
instead of degrading.

- [ ] **Step 1: Write the failing test**

```go
// The authoring database comes from the record's own identifier, resolved
// once at ingest. Every namespace the live database actually contains is
// covered, plus the nesting case that makes prefix-parsing at query time a
// bad idea: ALPINE-CVE-2025-46394 is an ALPINE record, not a CVE one.
func TestDatabaseOf(t *testing.T) {
	for in, want := range map[string]string{
		"GHSA-w24h-v9qh-8gxj":   "GHSA",
		"PYSEC-2022-191":        "PYSEC",
		"GO-2026-4970":          "GO",
		"ALPINE-CVE-2025-46394": "ALPINE",
		"CVE-2021-41092":        "CVE",
		"BIT-golang-2026-39822": "BIT",
		"MAL-2024-1":            "MAL",
	} {
		if got := databaseOf(in); got != want {
			t.Errorf("databaseOf(%q) = %q, want %q", in, got, want)
		}
	}
	// An identifier with no namespace is not silently given one. An empty
	// Database renders as a rating from a source with no name, which is
	// worse than a loud refusal.
	for _, bad := range []string{"", "nodashes", "-leading"} {
		if got := databaseOf(bad); got != "" {
			t.Errorf("databaseOf(%q) = %q, want empty", bad, got)
		}
	}
}

// Every record the provider emits carries a Database. A record without one
// produces a rating attributed to nobody, which is the opposite of what D25
// is for.
func TestConvert_SetsTheDatabase(t *testing.T) {
	for _, tt := range []struct{ id, want string }{
		{"GHSA-w24h-v9qh-8gxj", "GHSA"},
		{"PYSEC-2022-191", "PYSEC"},
		{"ALPINE-CVE-2025-46394", "ALPINE"},
	} {
		rec := `{"id":"` + tt.id + `","affected":[{"package":` +
			`{"ecosystem":"PyPI","name":"django"}}]}`
		got, ok, err := Convert([]byte(rec), "PyPI")
		if err != nil || !ok {
			t.Fatalf("Convert(%s) = ok:%v err:%v", tt.id, ok, err)
		}
		if got.Database != tt.want {
			t.Errorf("Convert(%s).Database = %q, want %q", tt.id, got.Database, tt.want)
		}
	}
}

// The schema bump is what stops an older database from serving records with
// no Database at all.
func TestSchemaVersionIs5(t *testing.T) {
	if store.SchemaVersion != 5 {
		t.Errorf("SchemaVersion = %d, want 5 — D25 adds a field, and a database "+
			"built without it must refuse rather than report unattributed ratings",
			store.SchemaVersion)
	}
}
```

- [ ] **Step 2: Run them, watch them fail**

- [ ] **Step 3: Implement**

```go
// databaseOf returns the database that authored an advisory, read from its
// identifier's namespace.
//
// Resolved once, at ingest, rather than at query time: a prefix is a naming
// convention rather than a field, and these identifiers nest —
// ALPINE-CVE-2025-46394 is an ALPINE record whose subject has a CVE. A parser
// in the read path would have to get that right on every call, silently.
func databaseOf(id string) string {
	i := strings.Index(id, "-")
	if i <= 0 {
		return ""
	}
	return id[:i]
}
```

- [ ] **Step 4: Run them, watch them pass**

- [ ] **Step 5: `db status` shows it**

`assay db status` already prints `covers:`. Add the databases present, using the same
collapsing style, so an operator can see what a rating could be attributed to without running
a scan.

- [ ] **Step 6: Commit**

```bash
git add internal/advisory internal/provider/osv internal/store internal/dbcmd
git commit -m "feat: record which database authored each advisory (D25)"
```

---

### Task 2: The matcher keeps what it currently discards

**Do not delegate.** CLAUDE.md reserves `Matcher` and `Evidence` for the main loop: the
reasoning that makes a finding explainable is the thing being built, and this task is exactly
that reasoning.

**Files:**
- Modify: `internal/matcher/matcher.go`, `internal/matcher/matcher_test.go`

**Interfaces:**
- Consumes: `Advisory.Database` from Task 1.
- Produces:
  ```go
  // Rating is one database's assessment of one vulnerability.
  type Rating struct {
      Database string          // "GHSA", "PYSEC", …
      AdvisoryID string        // the record this came from
      Severity severity.Band
      Score    float64
      Fixed    string          // the fixed version this record gives for this package, "" if none
  }
  // Finding gains:
  Ratings []Rating  // sorted by Database, then AdvisoryID. Always non-empty.
  ```
  `Finding.Severity` and `Finding.Score` keep their meaning and become the highest across
  `Ratings` (D25).

  **`Finding.Advisory` and `Finding.Evidence` come from the record that set the band** --
  highest rating wins, ties broken by database name. Not "whichever matched first".

  This was nearly left out of scope, which the plan's own done-when criterion contradicts:
  the JSON emits `advisory.id`, `advisory.summary` and `evidence.fixed` from this record, so
  leaving it order-dependent means two builds with reversed record order still produce
  different output -- and the fixed version differs between sources on 152 of the 169
  measured groups, so it is not a rare case. Tying the displayed record to the band also
  makes the report agree with itself: it says critical, and the advisory it shows is the one
  saying so.

**The shape of the change.** `matcher.go`'s `reported` map currently means "this vulnerability
is already reported, skip it". It becomes "this vulnerability already has a finding, attach
this record's rating to it".

- [ ] **Step 1: Write the failing tests**

```go
const vecCritical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // 9.8

// twoSources builds a store holding the same vulnerability twice — once as
// GHSA with a critical vector, once as PYSEC with none — in the given order.
// Both records claim CVE-2022-28347 so the matcher recognises them as one
// vulnerability, which is the shape measured on the live database.
func twoSources(t *testing.T, first, second advisory.Advisory) matcher.Store {
	t.Helper()
	return fakeStore{byKey: map[string][]advisory.Advisory{
		"PyPI\x00django": {first, second},
	}}
}

func ghsaRec() advisory.Advisory {
	a := advWithRange("GHSA-w24h-v9qh-8gxj", "PyPI", "django", "0", "2.2.28",
		advisory.RangeEcosystem)
	a.Database = "GHSA"
	a.Aliases = []string{"CVE-2022-28347"}
	a.Severity = []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}}
	return a
}

func pysecRec() advisory.Advisory {
	a := advWithRange("PYSEC-2022-191", "PyPI", "django", "0", "2.2.28",
		advisory.RangeEcosystem)
	a.Database = "PYSEC"
	a.Aliases = []string{"CVE-2022-28347"}
	// No Severity at all — this is what PYSEC records look like, and it is
	// the whole reason the aggregate matters.
	return a
}

// The measured case: two records, one vulnerability, different bands. Both
// are kept, and the finding is as severe as the worst of them.
func TestMatch_KeepsEverySourcesRating(t *testing.T) {
	res, err := matcher.Match(twoSources(t, ghsaRec(), pysecRec()),
		pkgmeta.Target{Packages: []pkgmeta.Package{
			{Name: "django", Version: "3.2.12", Ecosystem: "PyPI", Type: "pypi"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 - the two records are one vulnerability", len(res.Findings))
	}
	f := res.Findings[0]
	if len(f.Ratings) != 2 {
		t.Fatalf("got %d ratings, want 2: %+v", len(f.Ratings), f.Ratings)
	}
	if f.Severity != severity.Critical {
		t.Errorf("Severity = %v, want critical - the highest across sources", f.Severity)
	}
	got := map[string]severity.Band{}
	for _, r := range f.Ratings {
		got[r.Database] = r.Severity
	}
	if got["GHSA"] != severity.Critical {
		t.Errorf("GHSA rating = %v, want critical", got["GHSA"])
	}
	if got["PYSEC"] != severity.Unknown {
		t.Errorf("PYSEC rating = %v, want unknown - that record carries no vector", got["PYSEC"])
	}
}

// The ordering dependency this change exists to remove. The same two records
// are fed in BOTH orders and the finding must come out identical.
//
// This is the test that would have caught the defect: today the result
// depends on which record the index lists first, and nothing says so.
func TestMatch_RatingsDoNotDependOnRecordOrder(t *testing.T) {
	pkg := pkgmeta.Target{Packages: []pkgmeta.Package{
		{Name: "django", Version: "3.2.12", Ecosystem: "PyPI", Type: "pypi"},
	}}
	forward, err := matcher.Match(twoSources(t, ghsaRec(), pysecRec()), pkg)
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := matcher.Match(twoSources(t, pysecRec(), ghsaRec()), pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(forward.Findings) != 1 || len(reversed.Findings) != 1 {
		t.Fatalf("findings: forward %d, reversed %d", len(forward.Findings), len(reversed.Findings))
	}
	a, b := forward.Findings[0], reversed.Findings[0]
	if a.Severity != b.Severity {
		t.Errorf("Severity depends on record order: %v vs %v", a.Severity, b.Severity)
	}
	// Compared as a rendered string so the failure names the difference
	// rather than reporting "not deeply equal".
	if fmt.Sprint(a.Ratings) != fmt.Sprint(b.Ratings) {
		t.Errorf("Ratings depend on record order:\n  forward  %v\n  reversed %v", a.Ratings, b.Ratings)
	}
}

// D17 through the aggregate: a source that rated nothing must not pull a
// rated finding down. unknown is outside the ordering, not below it — so the
// aggregate of {critical, unknown} is critical, not unknown and not none.
func TestMatch_AnUnratedSourceDoesNotDiluteARatedOne(t *testing.T) {
	res, err := matcher.Match(twoSources(t, ghsaRec(), pysecRec()),
		pkgmeta.Target{Packages: []pkgmeta.Package{
			{Name: "django", Version: "3.2.12", Ecosystem: "PyPI", Type: "pypi"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[0]
	if f.Severity != severity.Critical {
		t.Fatalf("Severity = %v, want critical", f.Severity)
	}
	if f.Score != 9.8 {
		t.Errorf("Score = %.1f, want 9.8 - the score of the band that won", f.Score)
	}
}

// ...and a vulnerability every source left unrated is still unknown, never
// coerced into a band (D17).
func TestMatch_AllSourcesUnratedIsUnknown(t *testing.T) {
	a, b := pysecRec(), pysecRec()
	b.ID = "PYSEC-2022-999"
	res, err := matcher.Match(twoSources(t, a, b),
		pkgmeta.Target{Packages: []pkgmeta.Package{
			{Name: "django", Version: "3.2.12", Ecosystem: "PyPI", Type: "pypi"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[0]
	if f.Severity != severity.Unknown {
		t.Errorf("Severity = %v, want unknown - no source rated it", f.Severity)
	}
	if f.Score != 0 {
		t.Errorf("Score = %.1f, want 0", f.Score)
	}
	if len(f.Ratings) != 2 {
		t.Errorf("got %d ratings, want 2 - both sources are still recorded", len(f.Ratings))
	}
}

// A single-source finding still has exactly one rating. Ratings is never
// empty, so no renderer has to special-case its absence — an empty slice
// would make "no source said anything" indistinguishable from "we dropped
// them".
func TestMatch_ASingleSourceStillProducesOneRating(t *testing.T) {
	res, err := matcher.Match(fakeStore{byKey: map[string][]advisory.Advisory{
		"PyPI\x00django": {ghsaRec()},
	}}, pkgmeta.Target{Packages: []pkgmeta.Package{
		{Name: "django", Version: "3.2.12", Ecosystem: "PyPI", Type: "pypi"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[0]
	if len(f.Ratings) != 1 {
		t.Fatalf("got %d ratings, want 1: %+v", len(f.Ratings), f.Ratings)
	}
	if f.Ratings[0].Database != "GHSA" || f.Ratings[0].AdvisoryID != "GHSA-w24h-v9qh-8gxj" {
		t.Errorf("rating = %+v, want it attributed to the record it came from", f.Ratings[0])
	}
}

// Ratings are sorted. The point of this change is to stop depending on
// incidental ordering; emitting them in whatever order the index listed
// would reintroduce exactly that, one layer up, in the output instead of the
// verdict.
func TestMatch_RatingsAreSorted(t *testing.T) {
	go_ := ghsaRec()
	go_.ID, go_.Database = "GO-2022-0001", "GO"
	res, err := matcher.Match(fakeStore{byKey: map[string][]advisory.Advisory{
		// Deliberately not in sorted order.
		"PyPI\x00django": {pysecRec(), go_, ghsaRec()},
	}}, pkgmeta.Target{Packages: []pkgmeta.Package{
		{Name: "django", Version: "3.2.12", Ecosystem: "PyPI", Type: "pypi"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range res.Findings[0].Ratings {
		got = append(got, r.Database)
	}
	want := []string{"GHSA", "GO", "PYSEC"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("rating order = %v, want %v", got, want)
	}
}

// The fixed version differs between sources on 152 of the 169 measured
// multi-record groups, so each rating carries the one its OWN record gives.
// Taking it from the winning record would make every source appear to agree.
func TestMatch_EachRatingCarriesItsOwnFixedVersion(t *testing.T) {
	late := pysecRec()
	late.Affected[0].Ranges[0].Events[1].Fixed = "3.2.13"
	res, err := matcher.Match(twoSources(t, ghsaRec(), late),
		pkgmeta.Target{Packages: []pkgmeta.Package{
			{Name: "django", Version: "3.2.12", Ecosystem: "PyPI", Type: "pypi"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	fixes := map[string]string{}
	for _, r := range res.Findings[0].Ratings {
		fixes[r.Database] = r.Fixed
	}
	if fixes["GHSA"] != "2.2.28" || fixes["PYSEC"] != "3.2.13" {
		t.Errorf("fixed versions = %v, want GHSA 2.2.28 and PYSEC 3.2.13 - each "+
			"rating reports what its own record says", fixes)
	}
}
```

- [ ] **Step 2: Run them, watch them fail**

- [ ] **Step 3: Implement**

Replace `reported map[string]bool` with `reported map[string]int` holding the index of the
finding already emitted for that vulnerability, so a later record appends a rating instead of
being dropped. Aggregate the band with the existing `severity.Highest` rule applied across
ratings. Sort `Ratings` before returning.

- [ ] **Step 4: Run them, watch them pass**

- [ ] **Step 5: Mutation-check before committing**

Each must turn the suite red. Apply, confirm, revert:

| Mutation | Why it matters |
|---|---|
| a later record is dropped instead of appended | the defect, restored |
| the aggregate takes the first rating rather than the highest | order dependence, restored |
| `Advisory`/`Evidence` taken from the first match rather than the band-setting record | the displayed record goes back to depending on index order |
| the aggregate takes the *lowest* | a critical finding reported as unknown |
| `unknown` counts as below `none` in the aggregate | D17 coerced through the back door |
| `Ratings` returned unsorted | non-deterministic output |
| a rating's `Fixed` is taken from the winning record rather than its own | every source appears to agree |

- [ ] **Step 6: Commit**

---

### Task 3: The gate reads the aggregate

**Do not delegate.** This touches exit codes, which are contract.

**Files:**
- Modify: `internal/scancmd/scancmd.go`, `internal/scancmd/scancmd_test.go`,
  `cmd/assay/main_test.go`

**Interfaces:**
- Consumes: `Finding.Ratings` and the aggregated `Finding.Severity` from Task 2.
- `scancmd_test.go` already has `buildMatrixDB(t, []matrixAdv)`, `buildMatrixSBOM(t,
  []matrixPkg)`, `matrixAdv{id, pkg, fixed, vectors}` and `matrixPkg{name, purlType}`.
  **Extend `matrixAdv` with an `aliases []string` field** rather than writing a new builder:
  several records claiming one CVE is exactly the shape these tests need, and the existing
  builder already writes a real bbolt database. `cmd/assay/main_test.go` has
  `buildRunSeamFixture(t, dir)` for the `run()` seam.

`verdict` already reads `f.Severity`, which Task 2 redefines as the aggregate — so the gate
may need no change at all. **That is the trap.** A test that passes without any production
change proves nothing about this task. Prove the wiring instead:

- [ ] **Step 1: Write the failing test**

```go
// The scenario D25 exists for, end to end at the run() seam: one source
// rates a finding critical, another rates it not at all, and --fail-on
// critical must exit 1 regardless of which record the store lists first.
//
// Both orders are exercised. Before D25 one of them exits 0.
func TestRun_FailOnUsesTheHighestSourceRegardlessOfOrder(t *testing.T) {
	for _, order := range []string{"ghsa-first", "pysec-first"} {
		// build the DB in that order, scan, assert exit 1
	}
}

// And the mirror: a finding every source left unrated still does not trip
// --fail-on none (D17), no matter how many sources reported it. Three
// unrated sources are still unknown, and unknown is outside the ordering.
func TestRun_ManyUnratedSourcesStillDoNotTripFailOn(t *testing.T) {
	// buildMatrixDB and buildMatrixSBOM already exist in this file. Extend
	// matrixAdv with the aliases each record claims, so several records
	// describe ONE vulnerability - that is what makes them ratings rather
	// than separate findings. None carries a vector, so all three are
	// unknown.
	db := buildMatrixDB(t, []matrixAdv{
		{id: "PYSEC-2022-191", pkg: "unrated", fixed: "2.0.0", aliases: []string{"CVE-2022-28347"}},
		{id: "PYSEC-2022-192", pkg: "unrated", fixed: "2.0.0", aliases: []string{"CVE-2022-28347"}},
		{id: "GO-2022-0001", pkg: "unrated", fixed: "2.0.0", aliases: []string{"CVE-2022-28347"}},
	})
	sbom := buildMatrixSBOM(t, []matrixPkg{{name: "unrated", purlType: "golang"}})

	none := severity.None
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, sbom,
		Options{FailOn: &none}, &out, &errOut); code != 0 {
		t.Errorf("Run = %d, want 0 - unknown never trips a threshold (D17), "+
			"however many sources reported it; stdout:\n%s", code, out.String())
	}
}
```

- [ ] **Steps 2-4: fail, implement, pass**

- [ ] **Step 5: Mutation-check**

| Mutation | Must fail |
|---|---|
| the gate reads `Ratings[0].Severity` instead of the aggregate | both order cases |
| the gate reads the lowest rating | the critical case |
| `--fail-on none` fires on an all-unknown finding | the D17 case |

- [ ] **Step 6: Commit**

---

### Task 4: Showing them

**Files:**
- Modify: `internal/report/table.go`, `internal/report/json.go`,
  `internal/report/explain.go`, and their tests

**The table** keeps one row per finding and one SEVERITY cell — the aggregate — because the
table is the scannable view and a row that grows with source count stops being scannable.
When sources disagree, mark it: `critical (9.8) ⚠` or `critical (9.8) *`, with a footnote
naming the flag that shows the detail. Pick the marker and say why in your report.

**JSON** carries the full array. This is the machine-readable view and it is where a filter
would read from, so nothing is collapsed:

```json
"severity": "critical",
"score": 9.8,
"ratings": [
  {"database": "GHSA",  "advisoryId": "GHSA-w24h-v9qh-8gxj", "severity": "critical", "score": 9.8, "fixed": "2.2.28"},
  {"database": "PYSEC", "advisoryId": "PYSEC-2022-191",      "severity": "unknown",  "score": 0,   "fixed": "2.2.28"}
]
```

The golden file gains a multi-source finding. Keep it byte-for-byte.

**Explain** is where the disagreement belongs in full, since it is the "why" view (D10):

```
severity: critical (9.8)   [highest of 2 sources]
  GHSA   GHSA-w24h-v9qh-8gxj   critical (9.8)   fixed 2.2.28
  PYSEC  PYSEC-2022-191        unknown          fixed 2.2.28
```

- [ ] **Steps 1-4: tests first, then implement**

Use `cellAt` for any table-column assertion — it resolves a column by header offset and picks
the row by its ADVISORY cell. Do not add `strings.Contains` assertions over a rendered table.

- [ ] **Step 5: Mutation-check**

| Mutation | Must fail |
|---|---|
| the disagreement marker is never shown | table |
| the marker is shown when sources agree | table |
| JSON emits only the aggregate, dropping `ratings` | json + golden |
| `ratings` emitted in map order | golden (it is sorted) |
| explain prints only the winning source | explain |

- [ ] **Step 6: Commit**

---

### Task 5: End to end, and the docs

**Do not delegate.** The claim being checked is this plan's own, and the docs record a
decision.

- [ ] **Step 1: On the live database**

```bash
export ASSAY_DB_DIR=<the scratch database>
assay db update                      # schema 5; the old one must refuse first
assay scan django-3.2.12.cdx.json --output json
assay scan django-3.2.12.cdx.json --explain CVE-2022-28347
```

Report: how many of the 19 Django findings have more than one rating, how many disagree, and
whether the aggregate band matches what the pre-D25 build reported. **A difference is the
headline** — it means the old build was showing one source's opinion as the answer.

- [ ] **Step 2: The ordering claim, proven**

Build the database twice with the provider's record order reversed, scan both, and diff the
JSON. Before D25 they differ; after, they must be identical. If you cannot reverse the
provider's order cheaply, reverse the index array in a test-only seam and say so.

- [ ] **Step 3: Differential against grype**

grype reports one severity per match. Compare its band against our **aggregate** and against
each individual rating, and say which one grype agrees with — that tells us whether grype
also takes the highest, or prefers a particular source. Report it either way; it belongs in
the D18 divergence table.

- [ ] **Step 4: Mutation-test this plan's claims**

| Mutation | Must fail |
|---|---|
| a later record is dropped rather than appended | Task 2 |
| the aggregate takes the first rating | Task 2 |
| `unknown` sorts below `none` in the aggregate | Task 2 |
| the gate reads one rating instead of the aggregate | Task 3 |
| `Database` derived at query time from the ID prefix | Task 1 |
| `SchemaVersion` left at 4 | Task 1 |
| JSON drops `ratings` | Task 4 |

- [ ] **Step 5: Docs, both languages, same commit**

README: what a multi-source finding looks like, that the verdict takes the highest, and the
measured numbers (38% multi-source, 140 severity disagreements). Add a D18 divergence row for
whatever step 3 found. `docs/deferred-decisions.md`: record NVD ingestion as a deferral — the
mechanism accepts it, the data is a separate cost — with a revisit trigger.

- [ ] **Step 6: Commit**

---

## Done when

- A Django scan shows both GHSA and PYSEC for the CVEs they both cover, with their bands.
- `--fail-on critical` exits 1 on `CVE-2022-28347` whichever record the store lists first.
- A finding every source left unrated is still `unknown`, and still does not trip `--fail-on`.
- `Ratings` is sorted, non-empty, and identical across two builds with reversed record order.
- `assay db update` on a schema-4 database refuses with instructions.
- `--output json | jq '.findings[].ratings'` works.
- Every mutation in Task 5 Step 4 turns the suite red.

## Not in this plan

Ingesting NVD or any new provider — D25 is the mechanism, not the sources. Choosing a
*preferred* source, or letting the user pick one; the aggregate is the highest and that is the
whole rule. Reconciling disagreeing fixed versions into one answer — they are shown, not
merged. A *preferred-source* setting: the band-setting record is displayed because it
justifies the verdict, not because any database is held to be better than another.
