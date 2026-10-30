# QA 2026-10-30 — verification and fixes

This document answers the QA report of 2026-10-30. The report is at
`qa-2026-10-30/qa-report.md` and `qa-report.ko.md` in the QA workspace, with evidence in the
same folder. Every claim here comes from a command run on 2026-10-30 against the commits named
below, and section 9 lists those commands. Nothing was released, no database was published,
and nothing was deployed.

## 1. Baseline and change scope

**The QA's baseline.** QA ran at `2d0ae5d`, the D157 branch (PR #209), and reviewed `f824794`
(also on that branch) separately. Neither commit is on `main`. PR #209 was open and unmerged
on 2026-10-30.

**This verification's baseline.** `origin/main` at `650bedb` (Merge #207), checked out clean.
Each QA defect was reproduced at `650bedb` before it was fixed (section 3). D157 touches the
Ubuntu provider and `db push`; none of the defects below involves either, and the fix branch
shares no Go file with #209.

**The fix.** Branch `fix/qa-1030`, local only: not pushed, no PR. Ten commits on `650bedb`:

| Commit | Item |
|---|---|
| `e61e46c` | ① long lines |
| `3679652`, `a5b2ad5`, `70601ba` | ③ range order (fix, then two mutation-round tests) |
| `2f1166b`, `63c1b86` | ④ HTTP/2 retry (fix, then a mutation-round test) |
| `0bb17e4` | ⑤ VEX outer index |
| `a778d79` | ② toolchain floor and release binary scan |
| `f954506` | docs: roadmap EN; CHANGELOG and DESIGN, EN and KO |
| (follow-up) | docs: roadmap KO, and this document with its Korean copy |

The fix branch does not contain items ⑥ and ⑦. They are in PRs that were already open:
- ⑥ in #208 (branch `fix/a10-layer-shadowing`);
- ⑦ in #212 (branch `feat/d158-sarif-catalog-skips`).

## 2. Verdicts

| # | QA item | QA severity | Verdict on `650bedb` | Disposition |
|---|---|---|---|---|
| ① | A long line truncates Gemfile.lock, Cargo.lock and uv.lock | P2 | **Reproduced.** Two more readers had the same defect (requirements.txt, pom.properties) | Fixed, `fix/qa-1030` |
| ② | Release built with Go 1.26.9; GO-2026-6809 is fixed in 1.26.10 | P2 | **Reproduced** on an equivalent rebuild, not on the published asset (it could not be downloaded) | Enforced, `fix/qa-1030` |
| ③ | An opens-first OSV range widens single-version windows | P2 | **Reproduced** | Fixed, `fix/qa-1030` |
| ④ | No retry when an HTTP/2 blob body is reset | P2 | **Reproduced** | Fixed, `fix/qa-1030` |
| ⑤ | VEX naming the outer index of a nested index does not apply | P2 | **Reproduced** on both the `oci-dir:` and the registry paths | Fixed, `fix/qa-1030` |
| ⑥ | A non-regular upper-layer entry does not hide a lower package DB | P3 | **Reproduced** | Fixed in #208 (open) |
| ⑦ | Catalog-level skips produce no SARIF result | P3 | **Reproduced** | Fixed in #212 (open) |
| — | Alpaquita weekly breach (69 > 66) | — | **Not a regression:** advisory growth | Ceiling was already re-banded by `1c25df5` (#189); not changed here |

## 3. Per item

Each fix was written test first. The test was run red against the unfixed code and green
against the fix. Then each new call site and branch was mutated against a committed baseline,
and the suite was run again.

### ① A line over 64 KiB truncates a lockfile's inventory

- **Conditions.** A dir: scan of a Gemfile.lock, Cargo.lock, uv.lock or requirements.txt, or
  a jar's `pom.properties`, with any line over 64 KiB. A long comment or whitespace line is
  enough.
- **Impact.** Every package after the line vanished, and the reader reported success. The
  scan judged the rest as the whole file: exit 0, `components` counting only the packages
  before the line, nothing incomplete. A critical package below the line was a silent false
  negative. For `pom.properties` the keys after the line were lost, so the jar counted as "no
  version, not evaluated". That one was visible, but still wrong.
- **Cause.** Each reader split lines with `bufio.Scanner` and never read `Err()`. The scanner
  stops at its first token over 64 KiB with `ErrTooLong`, and the loop just ends. The QA named
  gemlock and tomlblock. A sweep of every `bufio.NewScanner` in `internal/cataloger` found two
  more with no `Err()` check: requirements and jar. requirements' own comment claimed the
  limit made it "fail loudly".
- **Fix.** Each reader splits the bytes it already holds (`bytes.Lines` / `strings.Lines`), so
  no line is too long to read. The limit was not raised and no error was ignored. The CR
  handling of `ScanLines` is kept. The files are already bounded by `source.MaxFileBytes`
  (D112).
  - `internal/cataloger/gemlock/gemlock.go:44`
  - `internal/cataloger/tomlblock/tomlblock.go:55`
  - `internal/cataloger/requirements/requirements.go:146`
  - `internal/cataloger/jar/jar.go:312`
- **Tests.**
  - `internal/scancmd/longline_test.go` `TestRun_QA1030_ALongLineDoesNotHideTheLockfileBelowIt`
    calls `Run` on a dir: target for four manifest types × {128 B, 70 KiB}, with
    `--fail-on critical` and `--fail-on-incomplete`. It asserts exit 1, the package below the
    line among the findings, and `components == 2`.
  - `internal/cataloger/jar/jar_test.go` `TestParse_PropertiesAfterALongLineAreRead`.
- **Verification run.**
  - **Red.** With each reader restored to `650bedb` (requirements) or mutated to stop at a
    line over 64 KiB (gemlock, tomlblock), the matching 70 KiB subtests fail. Gemlock fails 1
    subtest, tomlblock 2 (Cargo.lock, uv.lock), requirements 1. Jar's old `parseProperties`
    fails its test.
  - **Green.** All pass on the fix.
  - **The QA's own probe** (`matcher/runtime_qa_test.go`, unchanged) on the fix: every
    oversized row now reports `components 2`, `findings 1`, exit 1, identical to its
    short-line control. On `650bedb` the oversized rows reported exit 0.
- **Difference from the QA.** The QA's probe asserts exit 2 ("report as unread"). Its notes
  also accept "a deliberate complete-read implementation may instead legitimately detect the
  vulnerable package and exit 1". That is the path taken. A line that can be read is not
  input to refuse. So those six assertions still fail on the fix, by design, and their outputs
  match the controls.

### ② Release toolchain: GO-2026-6809

- **Evidence kept apart.** Four sources, each answering a different question:
  1. **The QA's source scan** (`govulncheck-cli.txt`) ran with local Go **1.26.7**: 10
     findings. Nine are fixed in **1.26.9**, so they do not apply to a binary built with
     1.26.9. Only GO-2026-6809 (crypto/x509, "distrust compromised intermediate
     certificates", fixed in **1.26.10**) does.
  2. **The release build log** (`release-build-log.txt:204`, 2026-10-27, v0.12.0) shows
     `go version go1.26.9 linux/amd64`. setup-go's `go-version: "1.26"` took the runner's
     cached patch release.
  3. **The published deliverable** (the v0.12.0 assets) was **not scanned**. Downloading
     release assets fails on this machine with a TLS handshake timeout, as it did for the QA.
  4. **An equivalent rebuild** was scanned instead. This tree was built for linux/amd64 the
     way GoReleaser builds it (`CGO_ENABLED=0 -trimpath -ldflags "-s -w"`):
     - built with `GOTOOLCHAIN=go1.26.9`: govulncheck v1.9.0 `-mode=binary` reports
       **GO-2026-6809** (found in crypto/x509@go1.26.9, fixed in go1.26.10), nonzero exit;
     - built with `GOTOOLCHAIN=go1.26.10`: "No vulnerabilities found", exit 0.
- **Required patch level today.** The official database (`vuln.go.dev`, read 2026-10-30)
  lists 21 stdlib and toolchain advisories modified since 2026-09-01. The highest fix on the
  1.26 line is **go1.26.10**, from GO-2026-6809 alone. The others are fixed in 1.26.9. go1.26.10
  is released (`go.dev/dl`).
- **Fix** (`a778d79`):
  - **The floor.** `go.mod` `toolchain go1.26.10`.
  - **`scripts/check-go-toolchain.sh`.** Compares `go env GOVERSION` against go.mod's
    toolchain line and fails if older. It runs in `release.yml` before GoReleaser and in
    `ci.yml`'s build job. It checks the toolchain a build actually used: with
    `GOTOOLCHAIN=auto` the go command switches up to the floor itself, and a runner pinned to
    `GOTOOLCHAIN=local` with an older Go fails.
  - **`scripts/release-vulncheck.sh`.** Runs govulncheck v1.9.0 (released 2026-10-11) in
    binary mode. `.goreleaser.yaml` runs it as each build's post hook, so the exact stripped,
    cross-compiled binary is scanned before archiving, signing or publishing. A finding fails
    the release.
  - **`internal/ciguard/toolchain_test.go`.** Holds the wiring in place: go.mod has a
    toolchain line, release.yml runs the check before GoReleaser, ci.yml runs it, and every
    GoReleaser build has the hook. It deliberately does not hold a version number; that
    number is go.mod's.
- **Verification run.**
  - **The check.** `sh scripts/check-go-toolchain.sh` prints "Go 1.26.10 meets go1.26.10"
    (exit 0). With `GOTOOLCHAIN=local` (Go 1.26.7) it prints "error: Go 1.26.7 is older than
    go1.26.10…" (exit 1).
  - **The scan.** `scripts/release-vulncheck.sh` on the two rebuilt binaries exits 1 for
    1.26.9 and 0 for 1.26.10.
  - **Mutation.** The ciguard test fails under each of four: the release step removed, the
    CI step removed, the hook removed, go.mod's toolchain line removed.
- **Not done.**
  - The fix does not rebuild or re-release v0.12.0.
  - A GoReleaser run was not executed locally; its hook syntax is GoReleaser v2's
    `builds[].hooks.post`. **The first tagged release after merge must be watched**, and so
    must a `goreleaser release --snapshot --clean` before the tag (section 8).

### ③ An opens-first range widens single-version windows (D154)

- **Conditions.** An OSV range whose events list both opens before both closes:
  - `[introduced 1, introduced 3, last_affected 1, last_affected 3]`;
  - `[introduced 1, introduced 2, fixed 1, fixed 3]`.
- **Impact.** False positives. With the first range, 2.0.0 was affected, and 4.0.0 in another
  order. With the second, 1.5.0 was affected. Exit 1 on `--fail-on`, with no incomplete check.
  On the published database there is no incidence (below).
- **Cause.** `splitDegenerate` paired an open only with the first close after it, before the
  next `introduced`, in file order. Neither window was taken out. The D154 tie rule (close
  before open) then read the range as `[1, 3]`. OSV recommends sorted events but does not
  require them; that was re-read 2026-10-30
  (https://ossf.github.io/osv-schema/#affectedranges-events-fields). The reference algorithm
  sorts and leaves ties unspecified.
- **Fix.** `internal/version/rangeeval.go`:
  - `pairByVersion` (`:359`) runs after the file-order pass and walks the remaining events in
    version order. It tracks whether a window is open just below each version X. If none is,
    each open at X takes a close at X, and the pair is judged on its own. If one is, one close
    stays in the walk to end it (D154's rule for windows that meet, unchanged), and only the
    closes beyond it pair.
  - `eventLess` (`:467`) is `sortEvents`' comparator, factored out so both use it.
- **Tests.**
  - `internal/version/rangeeval_ties_test.go` `TestInRange_QA1030_AWindowsCloseNeedNotFollowItsOpen`
    runs every ordering (24 each) of six four-event ranges:
    - two single-version windows;
    - an empty window and a real one;
    - two empty windows;
    - an empty window above a closed one;
    - and two controls: windows that meet, and a single-version window where a wider one
      closes.

    Evidence is asserted for the QA shapes and verdicts for every case.
  - `internal/scancmd/rangeorder_test.go` `TestRun_QA1030_EventOrderDoesNotWidenSingleVersionWindows`
    calls `Run` on a CycloneDX SBOM of npm 2.0.0, 3.0.0 and 4.0.0, with the events opens-first
    and in order. It asserts exit 1 and the finding on 3.0.0 alone.
- **Verification run.**
  - **Red on `650bedb`.** 134 assertion failures, including 2.0.0 and 4.0.0 judged affected.
  - **Green on the fix.** All existing A7/D154 tests pass unchanged.
  - **Mutation.** Seven, all caught:
    - the call removed;
    - the reservation removed;
    - the state never set, or always set;
    - groups of one;
    - unsorted;
    - any close taken.

    The "always set" survivor in round one was closed by two added ranges (`a5b2ad5`,
    `70601ba`). Removing the call also fails the `Run` test.
  - **The published database** of 2026-10-27, through the A7 harness: 536 tied ranges, 2,892
    probes at each range's own bounds. The output is **byte-identical** before and after: no
    verdict and no evidence changed in production data.
  - **The QA's own probe** (`matcher/prior-range_test.go`, unchanged): 3 of 7 subtests fail on
    `650bedb`, 7 of 7 pass on the fix.
- **Remaining limit.** Evidence, not verdicts. Where a file lists `[X,X)` as a separate window
  inside two windows that meet, D154's file-order pass takes it out. The evidence for a
  version below X then names `[open, final close)` rather than `[open, X)`. That has been so
  since D154, and the verdict is the same in every order.

### ④ An HTTP/2 stream reset mid-pull is not retried (D140)

- **Conditions.** `db update` (`Pull`) or `db build --seed` (`PullSeed`) against a registry
  speaking HTTP/2 that resets the stream after part of the database layer was sent.
- **Impact.** Availability. The pull failed on the first GET with
  `stream error: stream ID N; INTERNAL_ERROR; received from peer`, while a second manual run
  succeeded. Integrity was intact: the previous database stayed byte-identical and the temp
  file was removed. The QA observed the same.
- **Cause.** D140's `interruptedTransfer` recognised `io.ErrUnexpectedEOF`, `ECONNRESET`,
  `EPIPE`, `net.ErrClosed`, a failed socket read and a network timeout. HTTP/2's stream error
  is net/http's unexported `http2StreamError`, which matches none of them.
- **Fix.** `internal/dbcmd/pull.go`:
  - **A tagging transport.** `bodyTransport` (`:477`) wraps the registry transport on all
    three `remote.Image` sites. `taggedBody.Read` (`:489`) wraps every non-EOF read error from
    a response body as a `bodyReadError`, and `interruptedTransfer` (`:451`) retries it.
  - **Why tagging keeps the artifact's defects out.** It works by where the bytes come from,
    not by matching error text. go-containerregistry's digest and size check reads above that
    reader, and gzip's header and CRC are read above it, so a corrupt layer is never tagged.
  - **The context.** `unpackWithRetry` (`:427`) now takes the context and does not retry once
    it is done. A `--timeout` deadline used to read as a network timeout and be retried into a
    context that could not succeed.
  - **Unchanged.** The bound stays three attempts. Signature verification (D137) runs before
    the unpack and is not touched. The temp file is removed and the previous database kept.
- **Tests.** `internal/dbcmd/pull_http2_test.go`, over a TLS HTTP/2 `httptest` registry. The
  test asserts every GET of the layer is HTTP/2.
  - `TestPull_QA1030_AnHTTP2StreamResetIsRetried`: Pull and PullSeed, one reset; exit 0, two
    GETs, "retrying (2/3)", a usable database.
  - `TestPull_QA1030_GivesUpAfterThreeResetStreams`: exit 2, exactly three GETs, the previous
    database byte-identical, no `.tmp`.
  - `TestPull_QA1030_PermanentFailuresAreNotRetried`: a corrupt layer, a cancelled pull and a
    pull past a 2-second deadline. Each is exactly one GET, with no "retrying", the previous
    database byte-identical and no `.tmp`.
- **Verification run.**
  - **Red on `650bedb`.** The reset tests fail; the controls pass.
  - **Green on the fix.** The D140 tests (`TestPull_RetriesADownloadCutMidStream` and others)
    still pass.
  - **Mutation.** Six, all caught:
    - the transport removed from Pull, or from PullSeed;
    - the context guard removed (this survived until the deadline control was added);
    - the tag not applied;
    - the tag ignored;
    - the body not wrapped.
  - **The QA's own probe** (`db/http2_retry_test.go`, unchanged): fails on `650bedb`, passes on
    the fix (update and seed).

### ⑤ VEX naming the outer index of a nested index (D121)

- **Conditions.** An image reached through outer index → inner index → manifest, and a VEX
  statement whose product names the outer index digest.
- **Impact.** The statement was skipped and the finding stood: exit 1 where the producer said
  not affected. The outer digest is the one a registry reference by digest names, and the one
  `docker buildx imagetools` prints.
- **Cause.** `collectCandidates` (`internal/source/image.go`) replaced the parent at each
  level, so a candidate kept only its immediate index. `scancmd.vexTarget` matched only the
  manifest and that index.
- **Fix.**
  - **The chain.** Each candidate carries `outer []v1.Hash`, every index above its parent on
    the path from the requested index, outermost first (`image.go:460`). The slice is copied
    per child so siblings never share a backing array (`:516`).
  - **The report.** `PlatformChoice.OuterIndexDigests` (`platform.go:70`) carries it, and
    `catalogImage` passes it to `vexTarget` (`scancmd.go:745`).
  - **The JSON `image` record is unchanged** (no schema bump). The chain serves VEX scope
    only.
  - **Out of the chain.** A sibling index, another platform's manifest and an `oci-dir:`
    layout's own `index.json` are not on the path.
- **Tests.** `internal/scancmd/vexnested_test.go` `TestRun_QA1030_VEXNamingAnOuterIndexAppliesToTheImageItLists`.
  The fixture is an outer index holding the host-platform inner index plus a sibling index
  with a riscv64 image. It runs in three forms:
  - `oci-dir:` with descriptors without platforms (the config-sniff path);
  - a registry by digest of the outer index;
  - a registry by tag (the descriptor-platform path).

  Statements naming the outer index, the inner index or the manifest must apply (exit 0, one
  suppressed). Statements naming the sibling index, the other-platform manifest or an
  unrelated digest must not (exit 1, one finding).
- **Verification run.**
  - **Red on `650bedb`.** Only the three "outer" subtests fail; every control passes.
  - **Green on the fix.** The existing VEX, platform and index tests pass.
  - **Mutation.** Seven, all caught:
    - the outer digests dropped in `vexTarget`, or in `catalogImage`;
    - the parent not added to the chain;
    - the chain cleared at the config-sniff site, or at the descriptor site;
    - `PlatformChoice` not set;
    - the chain shared between siblings.
  - **The QA's own probes** (`input/nested_index_vex_test.go`, unchanged): the outer-index and
    registry cases fail on `650bedb` and pass on the fix, controls included.

### ⑥ A non-regular upper-layer entry does not hide a lower package DB (audit A10)

- **Status.** Fixed in PR #208, not in `fix/qa-1030`. The cause and fix are in #208's
  description and roadmap entry.
- **Verification run.** The QA's own probes, unchanged (`image/runtime_qa_test.go`
  `TestQA1030UpperNonregularHidesPackageDB` and `TestQA1030RegularAndWhiteoutControls`):
  - **On `650bedb`.** All four non-regular subtests fail: a directory with an opaque marker, a
    FIFO, a character device and a block device each give "want exit2, got 0". The controls
    pass.
  - **On #208's head** (`origin/fix/a10-layer-shadowing`). All pass, controls included.

### ⑦ Catalog-level skips produce no SARIF result (audit A16, D158)

- **Status.** Fixed in PR #212, not in `fix/qa-1030`.
- **Verification run.** The QA's own probe, unchanged (`TestQA1030CatalogIncompleteSARIF`):
  - **On `650bedb`.** The `sarif` subtest fails; table and JSON pass.
  - **On #212's head.** All three pass.
- **Exit codes are unchanged** (D36/D21). The new results are `assay/not-evaluated` with level
  `warning` or `note`, never a CVE rule.

### Alpaquita weekly: 69 against a ceiling of 66

- **The run.** The weekly of 2026-10-25/26 (run 40243397863) reported
  `alpaquita 69 / grype 56 / agree 47 / assay-only 22 / grype-only 9 / BREACH`, against
  `maxFindings 66`.
- **Before this review.** Commit `1c25df5` (PR #189, 2026-10-26) had already raised the
  ceiling to 138. Its stated evidence: agree unchanged at 47, assay-only 3 → 22, all new
  BellSoft records. This review did **not** change any floor or ceiling.
- **Independent check against the published database of 2026-10-27.** The records exist and
  were modified after the previous weekly (2026-10-19):

  | Record | Modified | Range on `Alpaquita:stream` | Package |
  |---|---|---|---|
  | BELL-CVE-2026-88831, 88833 and siblings | 2026-10-22 | busybox `[1.36.1-r1, 1.38.0-r6)` | busybox |
  | BELL-CVE-2026-88829 | 2026-10-24 | busybox, introduced 1.36.1-r1, no fix | busybox |
  | BELL-CVE-2026-108119 | 2026-10-22 | busybox `[1.36.1-r1, 1.38.0-r6)` | busybox |
  | BELL-CVE-2026-114406 | 2026-10-23 | `[20220614-r3, 20261020-r0)` | ca-certificates |

  The image's busybox 1.38.0-r2 is inside every busybox range. The new tuples are true
  positives by BellSoft's own data, and the matched set grype agrees on held at 47. **Verdict:
  advisory growth, not a regression.**
- **One correction to `1c25df5`'s message.** It calls the busybox CVEs "unfixed". On the
  `stream` key most of them carry a fix at 1.38.0-r6; only 88829 has none.
- **Still bounded.** The fix-carrying assay-only tuples remain under `maxAssayOnlyFixed: 41`
  (D146), so a false-positive surge is still bounded even with the doubled `maxFindings`.

## 4. Product checks

| Check | State on `650bedb` + fixes | Evidence |
|---|---|---|
| Exit 0 is not "safe" | Exit 0 means no finding at or above `--fail-on` among what was evaluated. It does not mean complete. Incompleteness is gated only by `--fail-on-incomplete[=target]` (exit 2, D21/D36). Without those flags, an incomplete scan can exit 0. The table, JSON and SARIF each carry the counts. | D11/D21/D36; `verdict()` in `scancmd.go`; ⑦ for SARIF |
| OS packages and Bitnami only, inside images | Application packages inside images are not read (D70). Since D141 every image scan says so on stderr and in SARIF (`assay/inventory-scope`), and JSON has `inventoryScope.applicationPackages: not-read`. | `TestRun_D141_*` |
| EOL vs supported vs unknown | EOL is the day after EOLFrom (A9). `--fail-on-eol` on an unanswered lookup warns and does not fail. A service needing a definite answer must treat "unknown" as its own policy outcome. | `TestRun_EOLUnknownWith*WarnsButDoesNotTrip` |
| Frozen data, builtAt and dataAsOf | `DataAsOf` (D12) is upstream currency. A scan warns when `BuiltAt` is over 7 days old (D139), and judges age per key the scan uses, a frozen key as old as its freeze (D113). Frozen keys are marked in table, JSON and SARIF (D110/D111). | `TestRun_D113_*`, `TestRun_D110_*`, `staledb_test.go` |
| SLE→Leap fix origin kept | A mirrored advisory discloses `crossMappedFrom` in JSON and `--explain` (D108/D128). A13 (#207) made the merged finding follow the displayed record. | `TestJSON_DisclosesCrossMappedFrom`, `TestExplain_DisclosesCrossMappedFrom` |
| Empty or partial inventory looks clean | **Partly open.** An empty CycloneDX `components[]` is exit 0 even with both incomplete flags. The table says the document contained no components and JSON counts 0. This is documented in deferred-decisions. Partial input, the long-line case, is fixed by ①. A service must enforce a minimum-inventory policy of its own. | QA `empty-sbom.*`; `docs/deferred-decisions.md` |

## 5. What remains unresolved, and why

1. **⑥ and ⑦ are not on `main`.** They need #208 and #212 merged; both were green in CI on
   2026-10-30. A release cut from `main` today has neither.
2. **The published v0.12.0 binaries are unscanned.** The download timed out. The scan was of
   an equivalent rebuild (②). The published v0.12.0 carries GO-2026-6809 per its build log,
   and only a new release fixes that.
3. **The GoReleaser hook has not run.** It has not executed in a real GoReleaser run (②).
4. **An empty SBOM exits 0.** This is a documented product policy, not changed here. It needs
   a service-level minimum-inventory rule.
5. **Evidence still follows file order** for windows that meet when a file lists `[X,X)`
   between them (③, D154 behaviour, verdict-neutral).
6. **The service operations layer is absent from the repository.** These are unverified
   release conditions, not built here (section 7).
7. **This machine's limits.**
   - `-race` was not run: there is no cgo toolchain. CI runs `go test -race ./...`.
   - The `upstreamvectors`-tagged tests (network oracles, live Red Hat and SUSE feeds) run
     only in CI.
   - Windows security software intermittently blocked freshly linked test binaries
     ("Access is denied" at link time). Every such run was retried until it built, and no
     result above comes from a run that did not build. This is an environment problem, not
     a defect.
8. **No load test, no full CVE adjudication, no live registry or customer-image scan.** None
   was run, and none is claimed.

## 6. Readiness

| Use | Readiness | Conditions |
|---|---|---|
| **Internal PoC** | **Ready** once `fix/qa-1030`, #208 and #212 are merged and CI is green | Run it on OS-package and Bitnami inventory. Present exit 0 as "no finding among what was evaluated". Use `--fail-on-incomplete=target`. |
| **Limited customer pilot** | **Conditionally ready** | Everything above, plus: a new release built at go1.26.10 or later, through the new floor and binary scan, with its archives re-verified (`gh attestation verify`, cosign checksum). Pilot targets passed to the CLI by a wrapper, not as raw customer strings. Scope stated as "OS packages and Bitnami in images; application packages from lockfiles and SBOMs only". A minimum-inventory rule for empty SBOMs. A per-pilot isolated credential environment (D118). |
| **Full external service** | **Not ready** | The deployment layer in section 7 does not exist in this repository and has not been verified. In-image application inventory (D70) is not built. Promote-after-sign or a retained known-good database (D137's mutable tag) has no operational SLO. |

## 7. Unverified release conditions: the service operations layer

The repository leaves these to the deployment (`docs/deferred-decisions.md`, "Safe handling
of externally supplied targets"). None exists here and none was verified:

- **Network.** Egress policy, and a registry host and DNS allow-list. There is no host
  allow-list, private-range DNS answers are fetched, and go-containerregistry's SSRF check
  covers redirects to IP literals only.
- **Input kinds.** A wrapper restricting what customers may name: no local paths, no
  `docker-archive:` or `oci-dir:`. `source.Classify` is the place to hook it.
- **Isolation.** A per-scan process or container sandbox, CPU, memory and disk quotas, and a
  concurrency cap. D112 bounds file copies (512 MiB per file, 2 GiB per scan) and `--timeout`
  bounds wall clock, but neither is a hard sandbox. A single large unwanted tar entry can delay
  cancellation.
- **Credentials.** A per-customer, per-job `DOCKER_CONFIG`, `REGISTRY_AUTH_FILE` and
  `ASSAY_REGISTRY_AUTH_*`. Without them a scan uses the host user's login (D118).
- **Database availability.** Promote-after-sign, or a retained known-good artifact, so a
  failed signature after `db push` does not leave clients refusing an unsigned tag (D137).
- **Monitoring.** D157's Ubuntu fix-state count is in the artifact annotation but not in
  `db status` or the table. That is an observability gap, noted by the QA, not a verdict
  defect.

## 8. Mandatory before the next release

1. Merge `fix/qa-1030`, #208 and #212 (and #209, #210 and #211 as planned). Confirm `main`'s
   CI is green with `-race` and the `upstreamvectors` steps.
2. Run `goreleaser release --snapshot --clean` once with go1.26.10 or later. Confirm the
   `release-vulncheck` hook ran for all six binaries and passed.
3. Tag only after that. In the tagged run, confirm "Hold the toolchain to go.mod's floor"
   printed `go1.26.10` or later, and that every hook passed.
4. Before tagging, re-read `vuln.go.dev` for stdlib fixes newer than go.mod's toolchain line,
   and raise the line if one exists. The hook would stop the release anyway; raising it first
   avoids a failed tag.
5. After #209 merges, watch the first nightly for D157's Ubuntu floor. After #210 merges,
   watch the first run of its grype install step.

## 9. Differences from the QA report

| Topic | QA | This verification | Why |
|---|---|---|---|
| Baseline | `2d0ae5d` (D157 branch) | `650bedb` (`main`) | `2d0ae5d` is not on `main`. Every defect was re-reproduced on `main`. |
| ① scope | gemlock, tomlblock | plus requirements.txt and pom.properties | A sweep of every `bufio.NewScanner` in catalogers found two more readers without `Err()` |
| ① expected outcome | exit 2 asserted (exit 1 accepted in notes) | exit 1 with the finding | The line is read completely, so nothing is unread |
| ② findings | 10 from govulncheck on Go 1.26.7 | 1 applies to the 1.26.9 release (GO-2026-6809) | Nine are fixed in 1.26.9. The local toolchain is not the release toolchain. |
| ② deliverable | — | an equivalent rebuild scanned; the published asset not | The download timed out on this machine |
| ③ | P2 false positive | confirmed; no incidence in the 2026-10-27 published DB | The A7 harness output was identical before and after |
| Alpaquita | breach to triage | growth; already re-banded by `1c25df5` | BellSoft records modified 10-22..10-24 cover the image's versions |

## 10. How to re-check

From the repository, on `fix/qa-1030`. Run `go` with `GOFLAGS=` set empty, because this
machine's default `-mod=mod` rewrites `go.sum`.

```
go vet ./...                                   # clean
gofmt -l .                                     # empty
go test -count=1 ./...                         # 56 packages ok, 2026-10-30
go test ./internal/version -run 'QA1030|A7'
go test ./internal/dbcmd   -run 'QA1030|Retr|Broken|Interrupt'
go test ./internal/scancmd -run 'QA1030'
go test ./internal/ciguard
sh scripts/check-go-toolchain.sh               # "Go 1.26.10 meets go1.26.10"
GOTOOLCHAIN=local sh scripts/check-go-toolchain.sh   # fails on an older local Go
```

To re-run the QA's own probes unchanged, add each QA test file into the package by
`go test -overlay`, one file per package:

| QA file | Package |
|---|---|
| `qa-2026-10-30/matcher/runtime_qa_test.go` | `internal/scancmd` |
| `qa-2026-10-30/matcher/prior-range_test.go` | `internal/scancmd` |
| `committed-review-2026-10-27/db/http2_retry_test.go` | `internal/dbcmd` |
| `committed-review-2026-10-27/input/nested_index_vex_test.go` | `internal/scancmd` |
| `qa-2026-10-30/image/runtime_qa_test.go` | `internal/scancmd`, on #208 and #212 |
