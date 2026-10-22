# Response to the 2026-10-22 source review

*English · [한국어](2026-10-22-source-review-response.ko.md)*

The review examined commit `0164c949d268453fbb2e1b0206a60117b7bf5015` (PR #178, the D131
merge) and reported six conditional correctness defects, each with a fixture, a probe and a
log. This document records, for each, whether it was confirmed, what was changed, how the
change was verified, what it touches beyond the defect, and what it leaves open — written so
that a reader with the repository and no other context can re-run every step. Decisions are
recorded in the roadmap as D132–D136; this is the account of the work.

Base: `main` at `0164c94` was the review's own commit, so nothing had been fixed in the
meantime. Branch: `fix/review-2026-10-22`. Commits, in order: `d02e91f` (#6), `82bfd0d` (#1,
#2, #3), `53d49aa` (#4), `1fa7ef2` (#5), one test tightening, then the documentation.

## 1. Each defect: confirmed, fixed, files

| # | Defect | Confirmed on `0164c94` | Resolved | Decision | Production files |
|---|---|---|---|---|---|
| 1 | npm alias cataloged under its install name | yes — the review's test failed as described: alias exit 0, 0 findings, Evaluated 1 | yes | D132 | `internal/cataloger/npmlock/npmlock.go`, `internal/pkgmeta/package.go` (`Location.Install`), `internal/report/json.go`, `internal/matcher/matcher.go` (location key) |
| 2 | Ubuntu/RPM markers skip other ecosystems' packages | yes — Go `+fips1`, `+esm1`, `-module+el9` each skipped, exit 0 under `--fail-on critical --fail-on-incomplete=target` | yes | D133 | `internal/matcher/matcher.go` |
| 3 | same-named binary ignores its source version | yes — `util-linux` 0 findings / 0 skips / exit 0 where `bsdutils` found 1 | yes | D134 | `internal/matcher/matcher.go` |
| 4 | an older delta discards a newer archive revision | yes — request order `HEAD archive → GET changes.csv → GET doc → GET archive`; the stale delta copy won | yes, both CSAF providers | D135 | `internal/provider/suse/{suse,delta,spool,csaf}.go`, `internal/provider/redhat/{redhat,delta,spool,csaf}.go` |
| 5 | an NVD score removal leaves the seeded rating | yes — Rejected and Awaiting Analysis both kept CVSS 9.8 through Annotate → bbolt → matcher | yes | D136 | `internal/provider/provider.go`, `internal/provider/nvd/nvd.go`, `internal/store/{store,bolt}.go`, `internal/dbcmd/{dbcmd,push}.go`, `internal/dbartifact/dbartifact.go` |
| 6 | `--fail-on-epss=NaN` disables the gate | yes — `0.5` exit 1; `NaN` and `nan` exit 0 with the finding printed | yes | bug fix, no decision | `cmd/assay/main.go` |

Nothing was fixed by skipping a check, hiding a warning or loosening a gate. #5 adds a
tolerance to the publish guard, but it is bounded by a count the build measured against the
store, and the guard still refuses a source vanishing entirely.

## 2. Reproduction before and after, and the verification run

Every probe the review shipped was re-run first, unchanged, against `0164c94` via
`go test -overlay`; all six reproduced. The probes that asserted the *wrong* behaviour were
then rewritten to assert the intended result, so each is a regression test that fails on the
old code and passes on the new. Where the review probed a helper, the regression test drives
the real call path and reads findings, skips and the exit code.

| # | Before (the probe's observation) | After (the regression test's assertion) | Tests |
|---|---|---|---|
| 1 | `dir:` scan of npm 11.16.0's lockfile for `utility-alias: npm:lodash@4.17.20` with lodash fixed at 4.17.21: exit 0, 0 findings | exit 1, 1 finding, purl `pkg:npm/lodash@4.17.20`, Evaluated 1 — for the regular entry, the v3 alias and the v1 alias; scoped alias and plain entry at the parser; a nested v1 alias's `Install` is its real path | `internal/cataloger/npmlock`: `TestParse_V3AliasEntryIsNamedByItsRegistryIdentity`, `TestParse_V1AliasEntryIsNamedByItsRegistryIdentity`; `internal/scancmd`: `TestRun_NPMAliasIsMatchedAsTheRegistryPackage`; `internal/matcher`: `TestLocationKey_DistinguishesInstallPaths` |
| 2 | Go `1.0.0+fips1` / `+esm1` / `-module+el9` beside a clean sibling: exit 0, 0 findings, 1 skip (`SkipCoverage`) | exit 1, 1 finding, 0 skips, Evaluated 2 for each; Ubuntu `+esm1` and stream-less Rocky `module+el9` still skipped with their reasons | `internal/matcher/lineage_scope_test.go` (4 tests); `internal/scancmd`: `TestRun_LanguageVersionsWithDistroMarkersAreJudged` |
| 3 | dpkg status `Package: util-linux`, `Version: 1:2.38.1-5+deb12u3`, `Source: util-linux (2.38.1-5+deb12u2)`, fix `2.38.1-5+deb12u3`: exit 0, 0 findings, 0 skips | exit 1, 1 finding, for both `bsdutils` and `util-linux`; at the matcher the source at the fix is clean and a binary-name lookup keeps the binary version | `internal/matcher`: `TestMatch_SameNameLookupComparesTheSourceVersion`, `TestMatch_BinaryNameLookupKeepsTheBinaryVersion`; `internal/scancmd`: `TestRun_DebianSameNameBinaryIsJudgedOnItsSourceVersion` |
| 4 | SUSE: HEAD at t0, changes row at t1 served as revision 1 (fixed `9.6p1-1.0`), archive GET at t2 holding revision 2 (fixed `9.6p1-1.1`): the record stored fixed `9.6p1-1.0`; installed `9.6p1-1.0` clean | the archive GET precedes the changes GET; the t1 row is never fetched; the record is fixed `9.6p1-1.1`; `DataAsOf` is t2. With the row on the cutoff and a stale served document, the archive copy is emitted last and counted (`1 archive documents newer than the copy the delta fetched`). The D129 control holds (equally-dated delta copy supersedes, 1 superseded). Mid-download regeneration restarts from byte 0. Red Hat: the same four | `internal/provider/suse/snapshot_test.go` (3), `spool_test.go`: `TestFetch_ArchiveRegeneratedMidDownloadRestartsFromZero`; `internal/provider/redhat/snapshot_test.go` (3), `spool_test.go`: same name |
| 5 | delta page `{"id": CVE, "vulnStatus": "Rejected"\|"Awaiting Analysis", "metrics": {}}` against a store holding NVD 9.8 for CVE: rating kept, finding critical, checkpoint advanced | at the provider: the NVD rating gone, another authority's kept, a rated CVE on the same page untouched, progress `1 returned without a score (rating withdrawn)`; at `db build`: only NVD's key removed, a rated-then-withdrawn CVE ends absent, `Withdrawn` = removals that existed, the seed's `Withdrawn` never carried; at the store: exact key, existence reported; at `db push`: a drop covered by withdrawals passes, anything more is refused, zero is refused | `internal/provider/nvd/withdraw_test.go` (2); `internal/dbcmd/withdraw_test.go` (3, incl. the guard table); `internal/store`: `TestWithdrawRating_RemovesOneSourceAndReportsWhetherItExisted` |
| 6 | `--fail-on-epss=0.5` exit 1; `=NaN`, `=nan` exit 0 with the finding in the table | `NaN`, `nan`, `+Inf`, `-Inf`, `Infinity` refused at parse naming the flag and value; through `run()`: exit 2, empty stdout, stderr names the flag; `0` and `1` remain valid | `cmd/assay/main_test.go` (2 new subtests), `cmd/assay/epss_nan_test.go` |

Verification run on the branch head: `gofmt -l cmd internal` empty; `go vet ./...` clean;
`go test ./...` passes (Windows amd64, Go 1.26.7, `CGO_ENABLED=0`, so without `-race`; CI runs
the race detector). The review's own overlay probes, run unchanged against the fixed tree, now
fail on their wrong-behaviour assertions and the npm one passes — the expected inversion.

Mutation testing, one line changed at a time with the suite as the oracle, after each commit:

| Scope | Mutations | Result |
|---|---|---|
| #6 | the old range check restored; `math.IsNaN` removed | 1 caught, 1 **documented equivalent** — `!(v >= 0 && v <= 1)` already rejects NaN; the explicit `IsNaN` stays for the reader |
| #2 | each ecosystem gate removed | 2 caught |
| #3 | the old `lookupName != p.Name` restored; source version applied unconditionally | 2 caught |
| #1 | v3 `name` ignored; `Install` dropped; v1 spec ignored; split on the first `@`; location key ignoring `Install` | 5 caught |
| #4 | always skip; never skip; delta revision zeroed (SUSE and Red Hat); regeneration check removed (both); delta cutoff ignoring the GET | 8 caught |
| #5 | every withdrawal counted; seed's count kept (two copy paths); guard ignoring withdrawals; guard allowing zero; artifact view dropping them; NVD never withdrawing; `db build` ignoring the interface; store always reporting existence; withdraw without flushing; override lost | 11 caught |

Totals: 29 caught, 1 documented equivalent, 0 unexplained survivors.

## 3. Effect on existing behaviour, and what remains uncertain

**Scan-side (#1, #2, #3, #6) — no database change.** The next release's binary judges
differently in exactly the four shapes above and nowhere else:

- #1 changes which *name* an aliased npm package is matched and reported under. The JSON report
  gains `locations[].install` (omitted when empty); a consumer keyed on `name` sees `lodash`
  where it saw `utility-alias`. Workspace entries whose directory differs from their package
  name are affected the same way, which is the correct reading of npm's `name` field. Entries
  without a `name` field are byte-identical to before.
- #2 removes two skips from non-Ubuntu and non-RPM ecosystems. Any package that was being
  reported "not evaluated" for one of these markers on a language ecosystem is now judged;
  `--fail-on-incomplete` counts drop accordingly. Ubuntu, Oracle and RPM behaviour is unchanged
  and held by the control tests.
- #3 changes the compared version for a dpkg package whose binary and source share a name and
  whose `Source:` field carries a version. Measured on the 2026-08 fixtures that drove D41: the
  "name (version)" form is 1–15 % of packages per image, and only the same-name subset of those
  moves. Direction: a package the source namespace says is still short of a fix is now found;
  one it says is fixed is clean. No other cataloger records a differing source version, so apk,
  rpm, pacman and SBOM inputs are untouched.
- #6 turns a silent no-op into exit 2. A pipeline that was passing `NaN` was running without
  the gate it configured.

**Build-side (#4) — procedure, not data.** The published artifact needs no rebuild: every
nightly re-downloads the archive and the race could only ever affect a build in which upstream
regenerated the archive during the run. Costs accepted: SUSE's pre-flight HEAD is gone (one
fewer request); a failing delta now fails after the 445 MB / 262 MB spool rather than before
it; the progress line gains one counter. Remaining uncertainty is recorded in
`deferred-decisions.md` (Known hazards): a document changed after the tarball was assembled
but before its `Last-Modified` is in neither until the next rebuild (D129's own lag, a day or
two), and an archive copy that is both newer and empty leaves the delta's record until the next
build — reachable only through a stale cache, and signalled by a non-zero
`ArchiveNewerThanDelta`.

**Build-side (#5) — schema-compatible metadata.** `store.Meta` gains `withdrawn` on a rating
source's provenance (omitted when zero) and the artifact-side `Meta` gains `RatingWithdrawals`,
derived from the database and never written as an annotation. No schema bump: older binaries
read the JSON unchanged. The publish guard's one new acceptance is a drop no larger than the
build's own measured withdrawals, never to zero. The count a nightly reports (`N returned
without a score`) will be dominated by *new* CVEs still awaiting analysis — those withdrawals
find nothing stored and are not counted — so the stored-removals line, not the returned line,
is the number to watch.

**Not measured on the published database.** The review's fixtures establish each defect, not
its prevalence. How many aliased npm packages, same-named dpkg packages with a divergent source
version, or withdrawn NVD scores are in real targets or the live artifact was not counted here;
the first two show up as diffs in the weekly scanner differential, the third as the
reconciliation run's own line (next section).

## 4. Database rebuild or data recovery

- #1, #2, #3, #6: none. The binary changes; the artifact is unaffected.
- #4: none. The fix is in the fetch procedure and takes effect on the next nightly.
- #5: **one operation is owed.** Ratings NVD withdrew before D136 are still in the published
  artifact and a nightly window never re-requests an unmodified CVE. One build with
  `NVD_SINCE_DAYS=120` — the API's maximum window, which reaches behind the 2026-08-14 start of
  the seed chain — re-returns every CVE modified since and withdraws the stale ones; `db push`
  admits the resulting drop by exactly the measured count. This is recorded in
  `docs/deferred-decisions.md` with the procedure. Until it runs, the published artifact's NVD
  ratings for CVEs rejected or un-scored since August are stale in the direction the review
  describes (a critical that is no longer one). How many is unknown; the run reports it.

## 5. Resolved versus proposed

Resolved in code on the branch: all six defects, with the regression tests, mutation evidence
and documentation above.

Proposed, not done: the `NVD_SINCE_DAYS=120` reconciliation build (an operation, deferred to a
build someone can watch); reading the first nightly's `ArchiveNewerThanDelta` and
`withdrawn` lines after merge; and the weekly differential's next run as the measurement of
how many real targets #1–#3 move.

## Re-running this review's steps

From the repository root, on the branch:

```text
go test ./internal/cataloger/npmlock ./internal/matcher ./internal/scancmd ./cmd/assay -count=1
go test ./internal/provider/suse ./internal/provider/redhat -run 'Snapshot|ArchiveIsDownloaded|ArchiveCopyNewer|AsNewAs|Regenerated' -count=1 -v
go test ./internal/provider/nvd ./internal/dbcmd ./internal/store -run 'Withdraw|RatingCountRegression' -count=1 -v
go test ./... -count=1
```

To watch the old code fail, check out `0164c94` and run the review's own overlay probes as its
document describes; to watch the new tests fail on the old code, run the test files above
against `0164c94` with `go test -overlay`.
