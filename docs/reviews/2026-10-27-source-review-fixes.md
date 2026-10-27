# Fixes for the 2026-10-27 source review

English canonical · [한국어](2026-10-27-source-review-fixes.ko.md)

The 2026-10-27 source review and its re-review (both against `0d09e22`) reported three P2
defects. Each was verified independently, fixed at its cause, held by regression tests that
run through the real call path and failed before the fix, and recorded as a decision: D150,
D151 and D152 in the roadmap. `main` was at `0d09e22` when the work started, so nothing had
been fixed already. The Oracle train-boundary candidate from the first review is unchanged and
is still not a confirmed defect: no released pre-fix build has been found.

| # | Defect | Decision | Fix needs |
|---|---|---|---|
| 1 | SPDX source relationship drops the source EVR | D152 (revises D143) | the new binary (scan-time) |
| 2 | `install.sh` passes base64 a positional file (macOS) | D151 | the next release's `install.sh` |
| 3 | An unreadable signature payload is filed as an invalid signature | D150 | the new binary for `db update`; the next `dbstatus` run (workflows use `go run`) |

None of the three needs a database rebuild.

## 1. SPDX source relationships kept the name and dropped the EVR (D152)

**Verified.** The re-review's real-advisory probe was rerun on `0d09e22`. It converts Red Hat's
CSAF document for CVE-2023-23920 with `redhat.convert`, then matches a minimal SPDX npm built
from nodejs. The result was one finding, matched through `nodejs`, with no skips. The source
had a name and no version. The real document was downloaded again, and it is byte-identical
to the reviewer's copy (sha256 `9f6b64f001ca1d045b6c…`). The first review's synthetic Fedora
probe was rerun too: mod_ssl `1:2.4.62-1.fc40` from httpd `2.4.62-1.fc40` against an httpd
fix of `2.4.63-1.fc40` gave exit 0, no finding, nothing incomplete.

**Cause.** D143 gave the binary its source rpm's name only. The matcher compares a lookup under
the source's name against `Source.Version` when there is one (D41), and against the binary's
own version otherwise. So npm `8.19.3` was compared with a nodejs fix of `16.19.1`, and
mod_ssl's epoch 1 sorted above an epoch-less httpd fix. D143 justified the empty version by
the image path, which records the binary's EVR as `Source.Version`. That is audit finding A4,
a defect itself.

**Fix.** `sourceRPMOf` keeps the source's EVR from its own purl (`pkgmeta.EVROf`: the `@version`
with the `epoch` qualifier prefixed when present and non-zero, the rule binary purls already
used). Files: `internal/cataloger/spdx/spdx.go`, `internal/pkgmeta/distropurl.go`. The matcher
is unchanged. Relationship eligibility, `upstream` precedence (name only), the binary-name,
source-name and provides lookups are unchanged.

**Before → after.**
- **Real CVE-2023-23920, fixed npm:** one Medium finding through nodejs → none.
- **Same document, npm built before the fix:** found → still found.
- **Synthetic mod_ssl from httpd:** exit 0 and missed → exit 1, found through httpd.

**Namespace check.** A source EVR is correct only if a record under the source's name describes
the source's versions. Fedora Bodhi records source NVRs. Red Hat's fixed lists name arch
binaries beside `.src`. In the real document, every same-platform `.src` and same-named binary
pair has the same EVR (7 of 7 once module-stream builds, which D80 scopes separately, are set
apart).

**Not in scope: A4.** The image path still records the binary's EVR as `Source.Version` in
`rpmdb/header.go`. SOURCERPM is a filename with no epoch, and the source epoch must not be
inferred from the binary's. A4 needs its own decision and a measurement over real images. This
fix uses only what an SPDX document states explicitly.

**Tests** (each failed before the fix where noted):
- `internal/scancmd/spdx_source_evr_test.go`: `TestRun_SPDXSourceRelationshipComparesTheSourceEVR`
  (failed: the fixed npm was reported) and `TestRun_SPDXSourceRelationshipDoesNotBorrowTheBinaryEpoch`
  (failed: mod_ssl missed).
- `internal/provider/redhat/spdx_source_evr_test.go`: `TestRealCSAF_SPDXSubpackageIsJudgedOnItsSourcesEVR`,
  on Red Hat's real document (`testdata/cve-2023-23920.json.gz`).
- `internal/cataloger/spdx/generates_test.go`: D143's `TestParse_A3_ASubpackageWithItsOwnReleaseKeepsItsSource`,
  which required an empty version, now requires `1:16.19.1-1.el9_2`. New:
  `TestParse_SourceEVRComesFromTheSourcePURLOnly` and `TestParse_ASourceWithNoVersionGivesNoEVR`.
  The `upstream` precedence test now also requires no version.
- Mutation testing: 6 mutations, all caught.
- The reviewer's probes were written to pass on the defect. After the fix they fail on their
  assertions of the old behaviour: the real CSAF probe sees 0 findings and
  `Source.Version=1:16.19.1-1.el9_2`.

## 2. install.sh could not decode a signature on macOS (D151)

**Verified.** Apple's base64 (text_cmds `bintrans.c`) reads input only on stdin or `-i`. A
positional file is a usage error there, so `base64 -d file` failed before openssl ran, and the
installer said the signature did not verify. A harness case with Apple's argument parser (C8)
failed on the unchanged installer.

**Fix.** `install.sh` uses `base64 -d <file`. The harness (`scripts/install_test.sh`) no longer
uses GNU-only flags (`base64 -w0`, `sha256sum --text`). It runs each case that sets environment
variables in a subshell, records failures in a file, and gained C8. CI runs it on macOS-latest.
Files: `install.sh`, `scripts/install_test.sh`, `.github/workflows/ci.yml`.

**Native macOS.** The first macOS run installed the genuine release with the fixed installer
(C1). It then failed eight cases on the harness: macOS's `/bin/sh` (bash 3.2, POSIX mode) keeps
`VAR=x` written before a shell function after the call, so one case's variables leaked into the
next. POSIX leaves this unspecified, and dash does not keep it. With subshells the whole harness
passes on macOS-latest: genuine install, tampered archive, stale, deleted and foreign
signatures, no verifier on `PATH`, key rotation, and C8. Signature checking is not weakened.

## 3. An unreadable signature payload was filed as an invalid signature (D150)

**Verified.** The re-review's independent caller test was rerun on `0d09e22`. The manifest-403
control passed, and the blob 403, 404 and 503 subtests failed: `signed:false`, a fresh
observation time, an empty `publishedError`.

**Cause.** `Verify` turned every `verifyLayer` error, a failed blob fetch included, into
`ErrNoKeyVerifies`.

**Fix.** A layer is invalid only when ggcr reports the bytes it received as wrong (digest,
size, content length) or a check on readable bytes fails. Every other payload read error marks
the layer unread: a registry error after retries (decided first, whatever its body says), a
network error, a stream cut short over HTTP/1 or reset over HTTP/2, a cancelled context, or a
kind not foreseen. The first version listed the transport errors instead, and the branch review
found an HTTP/2 stream reset still filed as invalid. Other layers are still tried, and any one
that verifies accepts. With none verified and one unread, `Verify`
returns `ErrSignatureUnreadable`, which `db update` and `dbstatus` already handle as a transport
failure. A blob whose bytes do not match its digest is still invalid. Files:
`internal/dbcmd/trust/verify.go`.

**Before → after.**
- **dbstatus on a signature blob 403/404/503:** `signed:false`, a new `observedAt`, an empty
  `publishedError` → the previous signed description is kept and the error recorded.
- **`db update` on a blob 403:** "does not verify under any key" → "fetch signature: …403…".
  The pull is still refused with and without `--allow-unsigned`.

**Tests:**
- `cmd/dbstatus/sigblob_test.go`: blob 403, 404 and 503 (all failed before).
- `internal/dbcmd/pull_sigblob_test.go`: blob 403, with and without `--allow-unsigned` (failed
  before).
- `internal/dbcmd/trust/verify_unreadable_test.go`, which covers:
  - each status is unreadable;
  - an unreadable layer beside a genuine one, in either order, still accepts;
  - an invalid layer beside an unreadable one is unreadable;
  - a digest-mismatched blob of the payload's own length, and a blob of the wrong length, are
    invalid;
  - a cut stream, a context ended mid-fetch, and a registry error quoting ggcr's wording are
    unreadable.
- `internal/dbcmd/trust/readfailure_h2_test.go`: an HTTP/2 stream reset mid-payload is unread
  (failed on the first version of the fix).
- The reviewer's probe now passes 4 of 4 (1 of 4 before).
- Mutation testing, two rounds:
  - against the first version, nine: seven caught, and two mutual equivalents in clauses since
    removed;
  - against the inverted rule, four, all caught, one only after the digest case was given the
    payload's own length.

## Validation

Run on Windows 11, Go 1.26, `GOFLAGS=-mod=readonly`, at the branch head:

- `go test ./...`: pass. `go vet ./...` and `gofmt -l`: clean.
- `scripts/install_test.ps1`: all cases pass under Windows PowerShell 5.1 and 7. install.ps1 is
  unchanged.
- `scripts/install_test.sh` on Git Bash: all cases pass. C5 is skipped on Windows, as
  designed. On CI, PR #199 run 40451869250, macOS-latest: every case passes, C5 and C8
  included. The Linux job passes too.
- The reviewers' probes, against the same overlays:
  - the trust probe passes 4 of 4 (1 of 4 on `0d09e22`);
  - the three SPDX probes, which assert the old behaviour, now fail on it.
- Mutation testing (main loop, committed baseline, one mutation at a time):
  - trust: 9 against the first version (7 caught, 2 mutual equivalents since removed), 4 against
    the final rule (all caught);
  - SPDX: 6 of 6;
  - shell harness: C8 fails on the unchanged installer.
- **Found while validating:** the Windows CI leg timed out (10 minutes) in
  `internal/dbcmd` twice on 2026-10-27, once on `main` itself. The cause was a test helper that
  wrote 7,249 ratings in 7,249 transactions, each with an fsync. It now writes them in one
  transaction (116 s to 16 s locally). Test-only.

**Not run.**
- No `-race` locally: there is no C toolchain here, and CI runs it.
- No live workflow, database rebuild or publish.
- No hands-on Mac outside CI.
- No run of the unchanged installer on a real Mac. The defect is shown by C8's
  Apple-semantics shim on GNU platforms; the fixed installer is shown on a real Mac by CI.
- The tagged live-feed tests were not rerun (unchanged code).

## Release and rebuild

- **D152 (SPDX)** is scan-time code: it reaches users with the next binary release. No database
  rebuild.
- **D150 (trust)** is in the binary (`db update`) and in `cmd/dbstatus`, which the workflows run
  with `go run` at the merged commit. So `status.json` is corrected from the first workflow run
  after merge, and `db update` with the next release. No database rebuild.
- **D151 (install.sh)**: the README pins `install.sh` by the release commit. The fixed script
  reaches macOS users with the next release, after `scripts/prepare-release.sh` and the README
  pin. Until then a Mac user can fetch `install.sh` from the merge commit, or use
  `go install` / the release page.

## Side effects and remaining limits

- D152 changes verdicts on SPDX input only, for rpm binaries linked by a relationship whose
  version differs from their source's. Findings that came from the cross-namespace comparison
  disappear (false positives such as the npm one). Findings it hid appear (such as mod_ssl).
  A4 on the image path is unchanged.
- D150 changes no install decision: an unreadable signature was refused before and still is.
  Only the error class and wording change, and `dbstatus` stops publishing false outages.
- D151 changes only how the signature reaches openssl. Linux behaviour is identical (C1–C8 pass
  on GNU base64 and dash).
- The Oracle train-boundary candidate is not acted on, for the reason the review gives.

## Re-verifying

From a clone at the merge commit (PowerShell or Git Bash):

```sh
GOFLAGS=-mod=readonly go test ./internal/cataloger/spdx ./internal/pkgmeta ./internal/scancmd ./internal/provider/redhat -run 'SPDXSource|SourceEVR|RealCSAF|A3_|NoVersionGivesNoEVR' -count=1 -v
GOFLAGS=-mod=readonly go test ./internal/dbcmd/trust ./internal/dbcmd ./cmd/dbstatus -run 'Unreadable|CutShort|ContextEnded|DoesNotMatchItsDigest|UnreadableSignatureBlob' -count=1 -v
sh scripts/install_test.sh          # C8 = Apple base64 semantics; C5 needs Linux/macOS
GOFLAGS=-mod=readonly go test ./... && go vet ./...
```

The reviewers' original probes, unchanged (`$R` = the review folder):

```sh
go test -overlay "$R/source-rereview-2026-10-27/trust/overlay.json" ./cmd/dbstatus -run TestIndependentReview -count=1 -v   # now 4/4 PASS
go test -overlay "$R/source-rereview-2026-10-27/spdx/overlay.json" ./internal/provider/redhat -run TestReReview20261027 -count=1 -v   # now FAILS: 0 findings
go test -overlay "$R/source-review-2026-10-27/matcher/overlay.json" ./internal/scancmd -run TestReview20261027 -count=1 -v   # now FAILS: bad behaviour gone
```

To see each defect come back, revert one file to `0d09e22` and rerun its test:
`git checkout 0d09e22 -- internal/cataloger/spdx/spdx.go internal/pkgmeta/distropurl.go`
(the SPDX tests fail), `-- internal/dbcmd/trust/verify.go` (the trust tests fail), or
`-- install.sh` (C8 fails). Evidence for the real advisory:
`internal/provider/redhat/testdata/cve-2023-23920.json.gz` is Red Hat's document
(sha256 `9f6b64f001ca1d045b6c…` uncompressed). Decisions: roadmap D150, D151, D152.
