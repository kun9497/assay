# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`assay` is a vulnerability scanner (Go, module `github.com/kun9497/assay`) that covers the
whole path in one tool: build the package inventory from an image/binary/directory, build
the vulnerability database, and match the two. In the anchore ecosystem those are three
separate projects (`syft`, `vunnel` + `grype-db`, `grype`). KISA/KNVD advisory data is a
first-class provider — that is the main reason this exists rather than using grype.

Slices ①–④ are built: `assay db update` builds a database from OSV (Go, npm, PyPI, Alpine),
and `assay scan` reads SBOMs, container images, Go binaries and directories, matches them,
and returns a verdict CI can gate on. A finding carries every source's rating and the gate
takes the highest (D25). Not built: the KISA provider (⑤, on hold — the data does not
support it, see `docs/deferred-decisions.md`), non-Alpine distros, npm/PyPI directory
scanning, SARIF, and NVD ingestion.

**Check what exists before assuming — this paragraph has been wrong twice.** It claimed
`scan` was unimplemented after slice 1 shipped it, and claimed binaries and directories were
unread after slice 3 shipped both. `README.md`'s roadmap checkboxes are the more reliable
record because they are edited task by task; this paragraph is edited from memory.

**Read these before proposing anything structural:**

- `docs/superpowers/specs/2026-07-29-assay-roadmap.md` — the reference design. Every
  decision is recorded as `D1`…`D26` with its reasoning. Cite the decision ID when
  discussing one.
- `docs/deferred-decisions.md` — **required before suggesting a feature.** Most obvious
  gaps (Debian support, RHEL support, VEX, prebuilt database artifacts, database age
  enforcement) are deliberate deferrals with recorded reasoning, a revisit trigger, and
  groundwork already in place. It also lists known hazards and the unverified assumptions
  the design rests on. Do not re-litigate an entry without new information; add to it when
  deferring something new.

## Commands

```bash
make build        # CGO_ENABLED=0, -trimpath, version/commit/date via -ldflags -> bin/assay
make test         # go test -race ./...
make lint         # go vet ./...
make fmt          # gofmt -l -w .
```

Run a single test: `go test -race -run TestRun_ExitCodes ./cmd/assay`

The Makefile shells out to `date` and `rm`, so on Windows either run it under Git Bash or
call the underlying `go` commands directly. CI (`.github/workflows/ci.yml`) runs
gofmt-check → vet → test -race → build on Go 1.26; a non-empty `gofmt -l .` fails the build.

**`make test` fails on a machine without a C toolchain**: `-race` requires cgo, and Go
defaults `CGO_ENABLED` to 0 when it finds no C compiler. Fall back to `go test ./...`
locally — CI still runs the race detector, so races are caught there.

`CGO_ENABLED=0` is also a real constraint on dependency choice — anything needing cgo
(notably `mattn/go-sqlite3`) is unavailable. It is part of why the store is bbolt (D4).

## Architecture constraints

Five interfaces carry the design; keep changes inside these boundaries.
`Source` → `Cataloger` → `Target{Distro, []Package}` → `Matcher` (using `Store` +
`Comparer`) → `Reporter`. `Provider` populates the `Store` out of band.

**The database is orthogonal to the scan** (D14). `Provider`s write it via `assay db
update`; a scan only reads. **A scan never fetches vulnerability data** — never
auto-download on a missing database; exit 2 with instructions instead.

Narrowed in slice 2b from "never a network call on the scan path", which
`assay scan alpine:3.19` cannot honour. Only the *target* may be fetched, and only when the
user names a remote one. A scan of an SBOM, a `docker-archive:` tarball, or an `oci-dir:`
layout still makes no network call at all — that is the air-gapped path, and it must stay
that way.

**Advisories are stored in OSV shape** (D1) — `affected[].ranges[]` with `introduced` /
`fixed` events. Every provider normalizes into that form rather than the store growing
per-source variants. Owning the schema is what makes the KISA provider possible at all.

**Store upstream records losslessly; derive at query time** (D13). Severity bands come from
stored CVSS vectors, not from values baked in at build time. Store fields that are not
needed yet — adding one later means rebuilding the database.

**Ecosystem keys include the distro release** (D6) — `Alpine:v3.19`, not `Alpine`, because
the fixed version differs per release. The distro itself lives on `Target`, not `Package`
(D7): an image is Alpine 3.19, its packages are not.

**`Package.Source` is load-bearing** (D8). Distro advisories are written against *source*
packages while installed packages are *binary* packages, so an advisory for source `openssl`
is unreachable by looking up `libssl1.1`. Dropping this produces false **negatives**, which
are silent. It applies to Alpine too — its OSV purls carry `?arch=source` — so it is needed
from slice 2. Populate at catalog time from dpkg's `Source:` or apk's `o:` field.

**Drop withdrawn advisories at ingestion** (D16), not at query time, so no code path can
forget the check. ~1% of records carry a `withdrawn` timestamp.

**`MAL-*` records are excluded** (D15) — a different finding class with no severity and no
fixed version. `Advisory.Kind` is stored anyway so enabling them later is a filter change,
not a schema change.

**Unknown severity is a band, not a default** (D17). Half of all advisories carry no
`severity` field. Never coerce absent severity to `low`; `unknown` sits outside the
`low < medium < high < critical` ordering rather than below it. Unknown findings are always
reported and always counted in the summary, do not trip `--fail-on <band>` on their own, and
are gated only by the explicit `--fail-on-unknown`. Severity vectors may be CVSS v3 or v4.

**A finding keeps every source's rating** (D25). Two databases routinely describe one
vulnerability and disagree: 8,893 of 19,715 measured CVE groups carry more than one record,
and 5,423 of those have one record rated where another is not. `Finding.Ratings` holds each
authoring database's own band, score and fixed version; `Finding.Severity` is the highest
across them and `Finding.Advisory` is the record that set it, so the report agrees with its
own verdict. **Never resolve a tie by arrival order** — that was the defect, not a harmless
coin flip. Findings group on *any* shared identifier, not the record's own ID, because a
KISA record and a GHSA one will share only a CVE.

**Flag names follow grype where semantics match** (D18) — it aids migration and makes the
differential testing scriptable. When a shared name gains different behaviour, add a row to
the divergence table in the roadmap. A silently divergent flag is worse than a differently
named one.

**Read both `aliases` and `upstream`** when joining on CVE ID (D3). OSV 1.7 puts the CVE
link in `upstream`; records exist with `upstream` and no `aliases`.

**Version comparison stays per-ecosystem** (D9). Debian epochs, RPM release ordering, semver
pre-release precedence, and Maven ordering genuinely disagree. Never collapse `Comparer`
implementations into a shared `compareVersions`. The signature is
`Compare(a, b string) (int, error)` — real-world version strings are sometimes malformed,
and treating an unparseable version as "not vulnerable" is a miss. Surface such packages as
skipped with a count.

**`Finding` carries `Evidence`** (D10). Explainability is goal #1; if the evidence is not in
the type it ends up in log lines and effectively does not exist.

**Freshness is measured from upstream data, not build time** (D12). `Provenance.DataAsOf`
records when the upstream data was current, separately from `Meta.BuiltAt`. A mirror serving
a stale snapshot fetched today must not report as fresh.

## CLI contract

Exit codes are contract, not implementation detail (`exitOK`/`exitFindings`/`exitError` in
`main.go`): `0` = clean, `1` = findings at or above `--fail-on`, `2` = could not run or the
result cannot be trusted.

**Precedence when more than one applies: `2` > `1` > `0`** (D11). An untrustworthy result
outranks the content of the result. This is fixed contract — changing it later breaks other
people's CI.

CI must never confuse "found nothing" with "was broken". Packages that cannot be evaluated
are reported as skipped with a count, never folded silently into a clean verdict — and that
obligation is on every renderer, not just the table: `--explain` shows one finding, so it
warns on stderr when the rest of the scan was incomplete, because otherwise it prints a
confident answer about a scan that did not finish.

`--fail-on <band>` reaches exit 1, `--fail-on-unknown` reaches exit 1, and
`--fail-on-incomplete` reaches exit 2 (D21). Unrated findings never trip `--fail-on` (D17).

**Stream discipline**: results to stdout, diagnostics to stderr, so
`assay scan ... --output json | jq` stays clean. `main_test.go` enforces both directions.

**`run(args, stdout, stderr) int` is the testable seam** — `main()` only translates its
return into `os.Exit`. New commands go in the `run` switch and take writers, never touching
`os.Stdout` or `os.Exit` directly.

## Testing

**Differential testing against grype is the primary correctness check.** Run the same SBOM
or image through both and compare. Exact agreement is not expected (the data sources
differ); a large divergence means the matcher is wrong.

`Store` is an interface, so test `Matcher` against an in-memory fake — no database needed.
**`Comparer` carries the highest test density**: table-driven, per ecosystem, covering deb
epochs, apk `-rN` suffixes, semver pre-release precedence, PEP 440 `.post` / `.dev`. That is
where false negatives originate.

## Documentation is bilingual

Every document ships as a pair: `X.md` (English) and `X.ko.md` (Korean). Currently
`README`, `docs/deferred-decisions`, and the roadmap spec.

**English is canonical.** Decisions are written there first; the Korean version follows.
When they disagree, English is correct and the Korean copy is stale.

**Update both in the same commit.** A translation that lags is worse than no translation —
it reads as authoritative while being wrong. If you change a decision in the roadmap, the
`.ko.md` change belongs in that same commit, not a follow-up.

Keep identifiers, flags, and file paths in English on both sides (`Package.Source`,
`--fail-on-unknown`, `/etc/os-release`). Translate the prose around them.

**Implementation plans under `docs/superpowers/plans/` are exempt — English only.** They
are working documents that change while being executed, so a translation would spend most
of its life stale, and they are mostly Go code blocks, which are never translated anyway.
Specs and user-facing documentation stay bilingual; plans do not.

## Delegating to subagents

Run the main loop on the work that needs full context; delegate work that is bounded,
independently verifiable, and parallel. The rule of thumb: **if the task's output is a
conclusion or an artifact you can check, delegate it. If it requires knowing why D1–D26 were
decided, keep it.**

**Delegate**

| Work | Why it fits | Model |
|---|---|---|
| Per-ecosystem version-comparison research — extract the ordering rules from a spec and produce a table-driven test case list | Bounded, one agent per ecosystem, fully parallel, output is checkable against the spec | Opus |
| Differential runs against grype — scan the same target with both, report divergences | Mechanical to run, and the output is a diff someone still has to judge | Sonnet |
| Data measurement against upstream dumps — record counts, size splits, field-presence surveys | Exactly the shape of the 2026-07-29 OSV measurement; produces numbers | Sonnet |
| Korean translation of a finished English document | Bounded, verifiable side by side | Sonnet |
| Codebase search across many files | Read-heavy, only the conclusion matters | Haiku or `Explore` |
| Bulk mechanical edits with a stated pattern | No judgement involved | Haiku |

**Do not delegate**

- **`Comparer` implementations.** Researching the rules parallelizes; writing the comparison
  does not. A subtle ordering bug is a **false negative** — silent, and the exact failure the
  per-ecosystem design exists to prevent (D9). Write these in the main loop and review the
  test table line by line.
- **`Matcher` and `Evidence`.** Explainability is goal #1, and the reasoning that makes a
  finding explainable is the thing being built.
- **Core types and interfaces.** They are cross-cutting; an agent seeing one slice will
  optimize for that slice.
- **Anything that would add or revise a `D` decision.** Those come from conversation with the
  user, not from an agent's judgement.

**Model assignment.** Match the model to the failure mode, not the task size. Use the
stronger model where a wrong answer is *quiet* — version-ordering rules, severity
normalization, anything that turns into a missed vulnerability. Use a cheaper model where a
wrong answer is *loud* — a failed build, a diff that obviously does not apply, a search that
returns nothing.

## Writing escape sequences into files

**Never type an escape sequence as a literal inside a script that generates a file.**
Assemble it instead — `chr(92) + "x00"`, `chr(92) + "u212a"` — and verify by scanning the
written file for the raw byte, not by trusting the tool's exit code.

A literal `\x00`, or a KELVIN SIGN typed as itself, in a heredoc, an editor buffer, or a tool argument loses a
backslash somewhere in transit and becomes **the byte it was meant to denote**. This has
happened three times on this branch: a KELVIN SIGN flattened to ASCII `K` (turning a test
that guarded Unicode case folding into one asserting a valid version was invalid), a raw NUL
in a Go map key (a hard `invalid NUL character` compile error), and a raw NUL inside the
comment that warned about the first two.

The failure is silent in prose and only sometimes loud in code, so grep for the codepoint
after writing:

```python
python -c "t=open('f','r',encoding='utf-8').read(); print(t.count(chr(0x212a)), t.count(chr(0)))"
```

Do not write the character literally in the checking script either — that is how the third
occurrence happened.

## Substring assertions that pass on the wrong column

**Never assert `strings.Contains(output, x)` when some other field in that output
already contains `x` as a substring.** Real identifiers nest: `ALPINE-CVE-2025-46394`
contains `CVE-2025-46394`, and an advisory ID of `CVE-2024-openssl` contains `openssl`.
The assertion then passes from the column you were not testing, and deleting the feature
entirely leaves the suite green.

This has happened twice on this branch — once checking that the report prints a source
package, once checking that it prints an identifier drawn from `upstream`. Both tests
looked correct, both were vacuous, and only mutation testing found them.

Pick fixture values that cannot collide (`ALPINE-2025-0001` with upstream
`CVE-2025-46394`), or assert the rendered pair (`libssl3 (openssl)`) rather than either
half. Then delete the code the test covers and confirm the suite goes red — a report test
that never fails is worse than no test, because it is counted as coverage.

## Guards that exist but are not held

**A guard is not covered by the test that mentions it.** The recurring defect in slice 3 was
not a missing test — it was a test that named the right thing and could not fail on it. Four
shapes, all found by mutation and none by reading:

- **A field declared, documented as the thing that prevents the defect, and never read.**
  `wantPkg` was populated in all three routing rows with a comment saying it stops a row
  passing on another row's output. Nothing referenced it. Discarding the cataloger's result
  entirely and fabricating an inventory left the whole repo green.
- **`continue` or `t.Skip` where the subject of the test lives.** `if !ok { continue }` in a
  loop asserting "everything this accepts is comparable" turns a *rejection* into a pass, and
  four inputs had no other coverage. A `t.Skip` at the top of a test skipped a second subtest
  that did not need the skipped-for tool at all — seven of eight mutations survived in that
  environment.
- **Asserting presence when order is the point.** The disclosure test checked that both the
  classification line and the error appeared. Making the disclosure a `defer` printed it
  *after* the error — the exact defect the test was added for — and stayed green.
- **A wrapper satisfying the assertion.** `Contains(err, "go.mod")` against
  `fmt.Errorf("read go.mod: %w", err)` passes on the hard-coded prefix, so an error that
  dropped both the filename and the cause was green. Same family as the substring rule above,
  but the colliding text is in the format string rather than a neighbouring column.

Before believing a test, ask what one-line change to the code it would **not** catch, then
make that change and watch it. If the suite stays green the test is documentation, not
coverage.

**A surviving mutation is not automatically a gap.** Several were true equivalents — a later
guard reaching the same answer, a level table entering only as a difference so a constant
shift cancels, two content sniffs that cannot both match one file. Verify which it is, then
say so in the code. An unexplained survivor reads as an untested branch forever; a documented
one reads as a decision. And check your mutation actually mutates: two "survivors" in this
slice turned out to be no-ops, and one needed edits in two places because the switch it
targeted is a whitelist.

## Conventions

- No third-party dependencies yet (`go.mod` has no `require` block). Adding one is a real
  decision — prefer the stdlib, and check the cgo constraint above.
- Comments explain *why* a choice was made (see the exit-code and TODO comments in
  `main.go`); match that register rather than narrating what the code does.
