# Slice 4 — Verdicts and Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** `assay scan alpine:3.19 --fail-on high` exits 1 when it should, 0 when it should,
and 2 when it cannot tell.

**Architecture:** Severity is derived from the stored CVSS vector at query time (D13), banded
into `none < low < medium < high < critical` with `unknown` outside the ordering (D17), and
compared against a threshold that decides the exit code (D21). Nothing about matching
changes.

**Tech Stack:** Go 1.26, `go.etcd.io/bbolt`, `go-containerregistry`. No new dependency —
the CVSS v4 lookup table is vendored data, not code.

---

## Scope note: SARIF is not in this slice

The roadmap lists slice 4 as "`--fail-on`, `--fail-on-unknown`, JSON / SARIF, explain mode".
SARIF is deferred. It is a separate schema with its own tool conventions, it is only useful
once a consumer exists (GitHub code scanning being the obvious one), and it can be added
without touching anything this slice builds — the reporter interface is where it plugs in.
JSON lands here because `--output json | jq` is what makes the findings usable at all, and
because the explain mode needs somewhere structured to explain from.

Record this in `docs/deferred-decisions.md` as part of Task 7 rather than leaving the
roadmap's list silently unfulfilled.

---

## Measured inputs

Measured 2026-08-01 against the live v4 database (31,996 records) and the FIRST reference
implementation. Do not re-derive; do not replace with estimates.

**Severity coverage is not 50% — that figure was Go-only.**

| Ecosystem | Records | With a vector |
|---|---:|---:|
| Alpine | 4,339 | **98.9%** |
| npm | 6,693 | 89.7% |
| crates.io | 39 | 87.2% |
| PyPI | 12,522 | 75.9% |
| Go | 8,502 | **49.7%** |
| **whole database** | **31,996** | **74.9%** |

D17 says "half of all advisories carry no severity". True of Go and of nothing else. A
container scan has almost no unknowns, which makes `--fail-on-unknown` far less noisy — and
more useful — than D17's framing suggests.

**Vector shapes.** 2,565 distinct vectors: **1,180 CVSS v3**, **1,385 CVSS v4**.
No record anywhere carries a numeric score — 0 of 31,996 have `cvss_score`, `base_score` or
`baseScore` — so the score must be computed. That is D13 working as designed, not a gap.

**Band distribution over the distinct vectors**, scored with an independent implementation:

| | none | low | medium | high | critical |
|---|---:|---:|---:|---:|---:|
| v3 | **10** | 144 | 597 | 354 | 75 |
| v4 | **2** | 264 | 627 | 408 | 82 |

`none` is populated in real data. Coercing 0.0 up to `low` would misreport twelve real
vectors, which is why D21 adds the band rather than folding it.

**Three data hazards, each found by running the real vectors through a parser:**

1. **One record's `type` contradicts its own vector.** `type: CVSS_V4` on
   `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`. Dispatch on the version prefix in the
   vector string, never on `Severity.Type`. The same vector appears correctly labelled
   elsewhere, so this is a per-record upstream error and will recur.
2. **A v4 vector carries a trailing slash**: `…/SC:N/SI:N/SA:N/`. One implementation rejects
   it outright. Decide deliberately — tolerating a trailing separator is safe; silently
   rejecting turns a scorable finding into `unknown`.
3. **v3 vectors carry temporal metrics**: `CVSS:3.1/…/A:N/E:U/RL:O/RC:R`. Banding uses the
   **base** score, so extra metrics must be ignored rather than treated as malformed.

**CVSS v4 has no single answer.** Two independent implementations — FIRST's own reference
calculator and RedHat's `cvss` library — disagree on **2 of 1,385** vectors, both by 0.1:

```
CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H   4.9  vs  5.0
CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N   5.6  vs  5.7
```

Pick FIRST's reference as the authority — it is the specification's own implementation — and
say so, so the divergence is a recorded fact rather than a bug someone finds later. Note that
0.1 can cross a band boundary in principle; neither of these two does.

**The v4 lookup table is vendorable.** `cvss_lookup.js` from FIRST's calculator is 270
macrovector entries, 4.5 KB, **BSD-2-Clause** — compatible with this repo's Apache-2.0,
unlike the apk vectors which had to be fetched at run time. Vendor the table with its
copyright header intact.

**A corpus can be generated.** `node` 24 is available, and the reference implementation runs
directly:

```bash
node gen.cjs "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
# 10   000100   CVSS:4.0/...
```

1,385 v4 vectors scored with zero errors. That corpus — expected scores for every v4 vector
in the real database — is the cross-check this task needs, and it is ours to commit because
the pairs are facts derived from our own data.

**grype's contract, for the divergence table (D18).** `-f, --fail-on` sets the return code
to **2**, and its bands are `negligible low medium high critical`. Both divergences are
already recorded in D18's table; the implementation must match D21, not grype.

---

## Global Constraints

- Go 1.26, stdlib plus the two existing dependencies. A third is a decision to raise.
- `CGO_ENABLED=0`. `make test` fails without a C toolchain; use `go test ./...`.
- **D21** — `--fail-on` exits **1**; `--fail-on-incomplete` exits **2**; bands are
  `none low medium high critical`; `unknown` is outside the ordering.
- **D17** — unknown findings are always reported, never coerced to a band, and never trip
  `--fail-on <band>` on their own. The unknown count is in the summary on every output path.
- **D13** — band at query time from the stored vector. Nothing is baked in at build time.
- **D11** — precedence `2 > 1 > 0`. An untrustworthy result outranks the content of the
  result, so `--fail-on-incomplete` firing beats `--fail-on` firing.
- **Stream discipline** — results to stdout, diagnostics to stderr, so
  `assay scan … --output json | jq` stays clean.
- Comments explain *why*. Match the register in `internal/version/apk.go`.
- Docs are bilingual (English canonical, same commit). Plans are exempt.

---

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `internal/severity/severity.go` | `Band`, its ordering, and `Of(vector string) (Band, float64, error)` |
| `internal/severity/cvss3.go` | v3.1 base score, transliterated from the formula |
| `internal/severity/cvss4.go` | v4.0 base score: macrovector + interpolation |
| `internal/severity/testdata/cvss_lookup.json` | the vendored 270-entry table, BSD-2-Clause |
| `internal/severity/testdata/v4-expected.tsv` | 1,385 vectors with reference scores |
| `internal/severity/testdata/v3-expected.tsv` | 1,180 vectors with reference scores |
| `internal/report/json.go` | `--output json` |
| `internal/report/explain.go` | explain mode |

**Modified**

| File | Change |
|---|---|
| `internal/matcher/matcher.go` | `Finding.Severity` |
| `internal/report/table.go` | SEVERITY column; unknown count in the summary |
| `internal/scancmd/scancmd.go` | gate evaluation; exit codes |
| `cmd/assay/main.go` | flag parsing |

---

## Task 1: Bands, and severity from a vector

**Do not delegate.** This decides what fails a build, and a wrong band is quiet.

**Files:** `internal/severity/severity.go`, `…/severity_test.go`

**Produces:**
- `type Band int` with `Unknown, None, Low, Medium, High, Critical`
- `func ParseBand(s string) (Band, error)` for the flag
- `func Of(vector string) (Band, float64, error)`
- `func (b Band) AtOrAbove(threshold Band) bool`

### The two rules that are easy to get wrong

**`Unknown` is not in the ordering.** `AtOrAbove` must return false for `Unknown` against
every threshold, including `None`. D17's whole point is that absent data is not a low score;
making `Unknown` sort below `None` would let `--fail-on none` sweep it in, which is coercion
with extra steps.

**Dispatch on the vector, not on the record's type.** One record in the live database says
`CVSS_V4` over a `CVSS:3.1/…` vector. `Of` takes the vector string alone for exactly this
reason — there is no type parameter to be wrong.

- [ ] **Step 1: Write the failing test**

```go
func TestBandOrdering(t *testing.T) {
	// The ordering CVSS defines, with the bands' numeric boundaries.
	for _, tt := range []struct {
		score float64
		want  Band
	}{
		{0.0, None}, {0.1, Low}, {3.9, Low}, {4.0, Medium}, {6.9, Medium},
		{7.0, High}, {8.9, High}, {9.0, Critical}, {10.0, Critical},
	} {
		if got := bandOf(tt.score); got != tt.want {
			t.Errorf("bandOf(%.1f) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

// D17: unknown is outside the ordering, not at the bottom of it. If it sorted
// below None, `--fail-on none` would sweep in every unrated finding — which is
// the coercion D17 forbids, arrived at from the other side.
func TestUnknownIsOutsideTheOrdering(t *testing.T) {
	for _, threshold := range []Band{None, Low, Medium, High, Critical} {
		if Unknown.AtOrAbove(threshold) {
			t.Errorf("Unknown.AtOrAbove(%v) = true; unknown never trips --fail-on", threshold)
		}
	}
	// ...and a threshold of Unknown is not a thing a user can ask for.
	if _, err := ParseBand("unknown"); err == nil {
		t.Error(`ParseBand("unknown") succeeded; --fail-on-unknown is the flag for that`)
	}
}

// The record's own type is not to be trusted: one live record labels a
// CVSS:3.1 vector as CVSS_V4.
func TestOf_DispatchesOnTheVectorNotTheLabel(t *testing.T) {
	b, score, err := Of("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")
	if err != nil {
		t.Fatal(err)
	}
	if b != Medium || score != 6.5 {
		t.Errorf("Of = %v/%.1f, want Medium/6.5", b, score)
	}
}

// A vector we cannot parse is Unknown, never a band. Guessing here is the same
// failure as coercing absent severity (D17).
func TestOf_UnparseableIsUnknown(t *testing.T) {
	for _, v := range []string{"", "nonsense", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"} {
		b, _, err := Of(v)
		if err == nil {
			t.Errorf("Of(%q) returned no error", v)
		}
		if b != Unknown {
			t.Errorf("Of(%q) = %v, want Unknown", v, b)
		}
	}
}
```

- [ ] **Step 2: Run it, watch it fail. Step 3: Implement. Step 4: Pass. Step 5: Commit.**

---

## Task 2: CVSS v3.1 base score

**Do not delegate.** Same reasoning as the apk comparer (D9): a transliteration where a
wrong answer is quiet.

**Files:** `internal/severity/cvss3.go`, `…/cvss3_test.go`,
`internal/severity/testdata/v3-expected.tsv`

### Build the corpus first

```bash
python -m pip install cvss
python - <<'PY'
from cvss import CVSS3
# vectors.tsv holds every distinct vector in the live database
out = []
for line in open('vectors.tsv', encoding='utf-8'):
    kind, vec = line.rstrip('\n').split('\t')
    if not vec.startswith('CVSS:3'):
        continue
    out.append(f'{CVSS3(vec).base_score}\t{vec}')
open('internal/severity/testdata/v3-expected.tsv', 'w', encoding='utf-8', newline='').write('\n'.join(out))
PY
```

1,180 distinct vectors. Commit the file — it is expected scores for our own data, not someone's
implementation.

### What the transliteration must handle

- **Temporal and environmental metrics are present and must be ignored.** A live vector
  reads `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N/E:U/RL:O/RC:R`. Banding uses the base
  score; treating the extra metrics as malformed would drop a scorable finding into
  `unknown`.
- **Scope changes the PR weights.** `PR:L` is 0.62 when `S:U` and 0.68 when `S:C` — the one
  place in the v3 formula where a metric's value depends on another metric.
- **Rounding is `roundup` to one decimal**, defined in the spec as the smallest number to
  one decimal place that is not less than the input. Naive `math.Round` disagrees on values
  that land exactly on a boundary, and those are common.

- [ ] **Step 1: the corpus replay test**

```go
func TestCVSS3AgainstReferenceScores(t *testing.T) {
	f, err := os.Open("testdata/v3-expected.tsv")
	// …for each line: parse "score\tvector", compute, compare exactly.
	// Report every mismatch, not just the first: a systematic error in one
	// metric shows up as a pattern, and stopping at the first hides it.
}
```

- [ ] **Step 2: Run it, watch it fail**

- [ ] **Step 3: Implement, from the specification's formula**

CVSS v3.1 §7.1, base score only. Weights:

```
AV  N .85  A .62  L .55  P .2
AC  L .77  H .44
UI  N .85  R .62
C/I/A  H .56  L .22  N 0
PR  S:U -> N .85  L .62  H .27
    S:C -> N .85  L .68  H .50      <- the scope-dependent pair

ISCbase = 1 - ((1-C) * (1-I) * (1-A))

S:U  Impact = 6.42 * ISCbase
S:C  Impact = 7.52*(ISCbase-0.029) - 3.25*(ISCbase-0.02)^15

Exploitability = 8.22 * AV * AC * PR * UI

Impact <= 0            -> 0
S:U                    -> roundup(min(Impact + Exploitability, 10))
S:C                    -> roundup(min(1.08 * (Impact + Exploitability), 10))
```

`roundup(x)` is the spec's own, not `math.Round`: the smallest number to one decimal place
that is not less than `x`. The spec gives an integer-arithmetic definition precisely because
floating point makes the naive version disagree on boundaries, and boundaries are where
bands change.

- [ ] **Step 4: Run the corpus. Every one of the 1,180 vectors must match exactly.**

- [ ] **Step 5: Commit**

```bash
git add internal/severity/cvss3.go internal/severity/cvss3_test.go         internal/severity/testdata/v3-expected.tsv
git commit -m "feat: score CVSS v3.1 vectors from the specification's formula"
```

---

## Task 3: CVSS v4.0 base score

**Do not delegate.** The hardest thing in this slice.

**Files:** `internal/severity/cvss4.go`, `…/cvss4_test.go`,
`internal/severity/testdata/cvss_lookup.json`, `…/v4-expected.tsv`

### It is not a formula

Scoring is: derive a six-digit macrovector from the metrics via the EQ1–EQ6 equivalence
classes, look the macrovector up in a 270-entry table, then **interpolate** — compute the
severity distance from the macrovector's highest-severity vector, divide by the
macrovector's depth, take the maximal scoring difference to the next-lower macrovector,
multiply, average across the equivalence classes, and subtract. The authority is FIRST's
reference implementation, not the prose.

### The authority, and the divergence

FIRST's reference is the authority. RedHat's `cvss` library disagrees with it on **2 of
1,385** live vectors, both by 0.1. Record that in a comment next to the corpus, with the two
vectors named, so the next person to cross-check against a different library finds the
answer rather than a mystery.

### Build the corpus and vendor the table

```bash
curl -sSL -o internal/severity/testdata/cvss_lookup.json \
  https://raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/main/cvss_lookup.js
# strip the JS wrapper to leave the JSON object; keep the copyright header in a
# sibling LICENSE note. BSD-2-Clause, compatible with this repo.

node gen.cjs < v4-vectors.txt > internal/severity/testdata/v4-expected.tsv
```

1,385 vectors, 0 errors when last run.

- [ ] **Step 1: the corpus replay test**, same shape as Task 2, plus:

```go
// The trailing slash a live vector carries. Rejecting it turns a scorable
// finding into unknown; the metrics before it are complete and unambiguous.
func TestCVSS4_ToleratesATrailingSeparator(t *testing.T) {
	got, err := scoreV4("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/")
	// …expect the same score as without it
}
```

- [ ] **Step 2: Run it, watch it fail**

- [ ] **Step 3: Implement, transliterating the reference**

The reference implementation is four files, all BSD-2-Clause, and between them they are the
whole algorithm:

| File | What it holds |
|---|---|
| `cvss_lookup.js` | the 270-entry macrovector table — vendor as data |
| `cvss_score.js` | `macroVector()` (EQ1–EQ6 derivation) and `cvss_score()` (interpolation) |
| `max_composed.js` | the highest-severity vector per macrovector level, for severity distance |
| `max_severity.js` | the per-EQ depth used as the interpolation denominator |

Fetch them into scratch, read `cvss_score.js` line by line against the Go, and keep the
structure recognisable — the same reasoning as the apk comparer, where a tidier rewrite is
how a quiet ordering bug gets in.

- [ ] **Step 4: Run the corpus. All 1,385 must match, and the two known divergences from
      RedHat's library must still be the only ones.**

- [ ] **Step 5: Commit**

```bash
git add internal/severity/cvss4.go internal/severity/cvss4_test.go         internal/severity/testdata/cvss_lookup.json         internal/severity/testdata/v4-expected.tsv
git commit -m "feat: score CVSS v4.0 vectors against FIRST's reference"
```

---

## Task 4: Severity on the finding, and in the table

**Files:** `internal/matcher/matcher.go`, `internal/report/table.go`, and their tests

`Finding` gains `Severity severity.Band` and `Score float64`, derived at match time from the
advisory's vector (D13). A record with several vectors takes the **highest** band — a
finding is as severe as its worst rating, and picking the first would depend on OSV's
ordering.

The table gains a SEVERITY column, and the summary gains the unknown count
**unconditionally** (D17): a threshold that hides how much it could not judge is not a
threshold.

- [ ] Tests, implementation, commit.

---

## Task 5: The gates and the exit codes

**Files:** `internal/scancmd/scancmd.go`, `cmd/assay/main.go`, and their tests

Three flags, and the precedence between them:

| Flag | Fires when | Exit |
|---|---|---|
| `--fail-on <band>` | any finding's band is at or above the threshold | **1** |
| `--fail-on-unknown` | any finding has an unrated severity | **1** |
| `--fail-on-incomplete` | any package was not evaluated | **2** |

**Precedence is D11's, unchanged: `2 > 1 > 0`.** If a scan both found a critical and could
not evaluate half the target, it exits 2 — the untrustworthy result outranks the content of
the result. State that in a test, because the opposite reading is intuitive.

- [ ] **Step 1: the table test over the matrix**

```go
// Every combination that changes the exit code, stated once so the contract is
// readable in one place. This is what CI depends on.
func TestRun_ExitCodeMatrix(t *testing.T) {
	// findings at/above threshold, unknown findings, unevaluated packages,
	// each flag on and off, and the 2 > 1 > 0 precedence between them.
}
```

- [ ] **Steps 2-5: fail, implement, pass, commit**

---

## Task 6: JSON output and explain mode

**Files:** `internal/report/json.go`, `internal/report/explain.go`, and their tests

JSON carries what the table shows plus what it cannot: the full `Evidence`, the source
package, the layer digest, the score alongside the band, and the same counts the summary
prints. It must be stable — a schema version field, sorted keys, and a golden-file test —
because a format that churns cannot be diffed in CI, which is design goal #3.

Explain mode prints one finding's `Evidence`: which range, which comparer, which comparison
result, and which name reached the advisory (D8/D10). This is goal #1 made visible, and it
is the reason `Evidence` is on the type rather than in a log line.

- [ ] Tests, implementation, commit.

---

## Task 7: End-to-end, and the docs

- [ ] **Step 1: the exit codes, on real data**

```bash
assay scan mirror.gcr.io/library/alpine:3.19                      # expect 0
assay scan mirror.gcr.io/library/alpine:3.19 --fail-on critical   # expect 0
assay scan mirror.gcr.io/library/alpine:3.19 --fail-on low        # expect 1
assay scan alpine-3.99.cdx.json --fail-on-incomplete              # expect 2
```

Report the band of each of the ten real Alpine findings. Two of them are `CVSS_V4`, so this
exercises Task 3 on data, not fixtures.

- [ ] **Step 2: differential against grype's severities**

grype prints a severity per match. Compare band-for-band on the same image. Divergence is
expected where the data sources differ, but a *systematic* shift — everything one band low —
means the scorer is wrong, and that is what this check is for.

- [ ] **Step 3: mutation-test this slice's claims**

| Mutation | Must fail |
|---|---|
| `Unknown` sorts below `None` | Task 1 |
| band boundaries off by one (`>=7.0` → `>7.0`) | Task 1 |
| v3 scope-dependent PR weight fixed to the `S:U` value | Task 2 |
| `roundup` replaced by `math.Round` | Task 2 |
| v4 interpolation dropped, macrovector score used raw | Task 3 |
| `Of` dispatches on `Severity.Type` | Task 1 |
| a finding takes the first vector rather than the highest band | Task 4 |
| `--fail-on-incomplete` exits 1 | Task 5 |
| precedence inverted, so 1 beats 2 | Task 5 |

- [ ] **Step 4: docs, both languages, same commit**

README: exit codes now reachable, the flags, the bands and how they map to CVSS, and the
grype divergences. `docs/deferred-decisions.md`: SARIF, with the reason and a revisit
trigger.

---

## Done when

- `--fail-on high` exits 1 on an image with a high finding and 0 on one without
- `--fail-on-incomplete` exits 2, and beats `--fail-on` when both apply
- An unrated finding is reported, counted in the summary, and does not trip `--fail-on`
- Both scorers agree with the reference corpus on every vector in the live database
- `assay scan … --output json | jq` is clean, and stderr carries the diagnostics
- Explain mode prints a finding's evidence
- Every mutation in Task 7 Step 3 turns the suite red

## Not in this slice

SARIF (recorded as a deferral), EPSS and KEV enrichment, `--sort-by`, and severity from
anything but the stored CVSS vector — NVD enrichment for the 25% with no vector is named in
D17 as a possibility, not a plan.
