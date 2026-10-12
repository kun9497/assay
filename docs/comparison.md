# assay · grype · trivy — a comparison

*Feature columns snapshot 2026-08-27, against assay v0.2.0, grype v6, and the trivy.dev
documentation as read that day. The assay↔grype numbers in the parity table were
**refreshed from the 2026-10-12 weekly run** (GitHub Actions run 38187900074) against assay
v0.8.0, grype v0.116.1 and trivy v0.74.0 — the same digest-pinned images run through both
scanners in the weekly differential (D93), tuple counts after the tool's normalization.
The trivy column remains a **spec comparison** from its official documentation as of
2026-08-27 — trivy joined the weekly differential in D105 and now runs on 18 of the 25
targets; per-row trivy figures below keep their original dates.*

## Structure and character

| | grype ecosystem | trivy | assay |
|---|---|---|---|
| Shape | Three projects: syft (inventory), vunnel + grype-db (database), grype (matching) | One multi-scanner: vulnerabilities + misconfiguration (IaC) + secrets + licenses | One vulnerability-only binary: inventory → match → verdict |
| Database | Built and published by separate tooling | Auto-downloaded on scan by default — convenient, but the scan path makes network calls; air-gap needs a separate offline procedure | Pulled explicitly by `assay db update`; a scan **never** fetches (D14) — SBOM and local-tarball scans make zero network calls |

## Coverage

| Area | assay | grype | trivy | Notes |
|---|---|---|---|---|
| Common OS families | ✓ | ✓ | ✓ | Alpine, Debian, Ubuntu, RHEL, Rocky, Alma, Amazon, Oracle, SLES/Leap, Wolfi, Chainguard, MinimOS, Echo, Azure Linux, Photon — all three cover these |
| Fedora · Arch | ✓ (D75, D97) | ✓ | ✗ | Both absent from trivy's supported list (CentOS Stream explicitly unsupported too) |
| Alpaquita · Hummingbird · CleanStart | ✓ (D95, D98, D101) | partial | ✗ | grype ships a Hummingbird provider; Alpaquita and CleanStart are assay-only |
| openSUSE Leap · SLE | ✓ | ✗ no data in v6 | SLE ✓, Leap measured empty | On SLE BCI trivy is real but speaks a different vocabulary: it keys findings by SUSE-SU patch advisory with the CVE only inside References URLs — the first D105 measurement wrongly read as "trivy found nothing" until the differential learned to extract those CVEs (agree 182/188 with assay once it did). On the Leap 15.6 image trivy genuinely returns an empty vulnerability list (it flags the release EOSL) where assay reports 12 — that target stays informational |
| Bottlerocket · CoreOS | ✗ | ✗ | ✓ | trivy-only |
| Language ecosystems | 8 | 8 | broader | The common eight (Go, npm, PyPI, crates.io, Maven, RubyGems, NuGet, Packagist); all three read pnpm and yarn berry lockfiles (assay since D103); trivy additionally covers Conan, Dart, Swift, Elixir. assay reads its eight only from a directory, lockfile, jar or Go binary named as the target — **not from inside a container image** (D70, deferred). grype catalogs installed language packages inside images (measured: the SLES and RHEL rows below), and trivy's documentation lists them for image targets — though invoked the way the differential runs it, trivy returned only OS results on both, so it corroborates neither side |
| Enrichment gates | NVD · EPSS · KEV · EOL | NVD · EPSS · KEV · EOL | none built in | trivy is severity-centric; it does not gate on EPSS/KEV/EOL natively |
| KISA / KNVD | ✓ first-class | ✗ | ✗ | The reason assay exists rather than reusing an existing tool |
| Beyond vulnerabilities | ✗ (deliberate) | ✗ (deliberate) | misconfig · secrets · licenses | trivy is a multi-scanner — a different scope, not a gap |

## Measured parity — per family, counts from the 2026-10-12 weekly run

The same digest-pinned images through both scanners, compared tuple by tuple — first
measured 2026-08-24 over 13 targets, now 25 targets weekly with trivy alongside on 18 of
them (D105, D114), and re-audited in full on 2026-08-28 (every one-sided tuple classified;
the audit's record lives in deferred-decisions). The **Result** column carries the
2026-10-12 weekly run's counts (agree / assay-only / grype-only); the **Cause** column keeps
the 2026-08-28 audit's classification, with its date wherever a figure is older than the
run — counts moved since, the classification was not redone. Where trivy corroborates a
side, the row says so.

| Family | Result | Cause of divergence | Verdict |
|---|---|---|---|
| Alpine | 10 agree, 0 assay-only, 4 grype-only (alpine319) | grype's +4 are its CPE-fallback matcher — a thing assay deliberately lacks (classified 2026-08-24) | exact parity |
| Ubuntu | 168 agree, 38 assay-only, 0 grype-only (ubuntu2204) | assay-only grew from 5 (2026-08-28 audit, where they were recent USNs grype lacked) to 38 on this run; the 38 are not re-classified. wont-fix 17/17 over 10 CVEs was exact on 2026-08-28 (D85) and is not re-measured here | assay ahead |
| AlmaLinux | 202 agree, 1 assay-only, 592 grype-only (alma9) | the 592 are OS-type tuples. On 2026-08-28 the fixable set was equal (110/0/0) and grype's then-512 extras were all not-fixed/wont-fix Red Hat data substituted for Alma; the fixable restriction is not re-derived for 2026-10-12 | exact parity on fixables (08-28) |
| Amazon Linux 2023 | 83 agree, 0 assay-only, 1 grype-only (az2023) | the 2026-08-28 audit's 0 = 0 no longer holds; the single grype-only tuple is not classified | near parity |
| Wolfi | 12 agree, 34 assay-only, 44 grype-only (wolfi) | the 2026-08-28 audit's 0 = 0 no longer holds (assay 46, grype 56); neither side's extras are classified yet | not classified |
| Debian | 242 agree, 5 assay-only, 0 grype-only (debian12) | on 2026-08-28 the then-6 assay-only tuples were grype DB gaps and 1 was an arguable assay FP (zlib1g/MiniZip); the current 5 are not re-classified | assay ahead |
| Rocky | 407 agree, 2 assay-only, 631 grype-only (rocky9) | the 2 assay-only came from the defective RLSA-2023:6699 on 2026-08-28 (peridot#204; not re-verified); the 631 grype-only are OS-type tuples, and the 2026-08-28 audit found grype's 68 *fixable* extras were Red Hat data substituted for Rocky, trivy confirming zero of them — that fixable figure is not re-derived | assay ahead (08-28) |
| Oracle | 143 agree, 0 assay-only, 84 grype-only (ol9) | grype-only tuples are FIPS-lineage ELSAs matched against mainline — assay's refusal (D79) is the correct side (classified 2026-08-28; the 84 are not re-split) | assay ahead |
| Fedora | 82 agree, 26 assay-only, 32 grype-only (fedora) | 16/16 at advisory level and 100% of one-sided CVE tuples inside shared advisories on 2026-08-28; the bare-advisory bridge recovered 11 then. Not re-checked at advisory level for this run | bidirectional, bounded (08-28) |
| openSUSE Leap | 0 agree, 284 assay-only, 0 grype-only (leap156) | grype v6 carries no Leap data at all (zero matches on 2026-08-28 and again on 2026-10-12) | assay only |
| SLES (bci-base) | 395 agree, 8 assay-only, 46 grype-only (bci156) | all 46 grype-only tuples are `go-module` — the Go standard library compiled into `/usr/bin/container-suseconnect`, a binary inside the image that an image scan does not read (D70 — inventory, not data model); 33 on the 2026-09-27 run, 46 on 2026-10-12. D117 now bounds it: `maxGrypeOnlyApp.go-module` is 92 for this target, so growth shows in the weekly run instead of being judged `ok`. The 2026-08-28 data-model split (fixable-restricted 180/0/65: assay expresses no-fix entries grype cannot; D91's fold) is not re-derived | data-model split + inventory gap |
| Azure Linux 3.0 | 294 agree, 31 assay-only, 0 grype-only (azl3) | Was the audit's one real assay gap (106 agree, 140 grype-only on 2026-08-28): Microsoft's OSV export bot had stalled 2026-03-10 and OSV.dev served the frozen snapshot. D106 moved the family to Microsoft's daily OVAL; assay is now 31 ahead of grype. The trivy 277/277 alignment was measured 2026-08-31 and is not re-measured. Both upstreams fixed their pipeline within a day of being notified | **assay ahead** |
| RHEL (ubi8-nodejs) | 1319 agree, 5008 assay-only, 47 grype-only (ubi8n18) | 98% of assay's extras were `kernel-headers` on 2026-08-28 — Red Hat's CSAF product tree lists it for kernel CVEs; grype never emits the package and trivy confirmed 4,078 of assay's tuples then (neither re-measured; the extras grew from 4531 to 5008). The other direction is an inventory gap: of the 47 grype-only tuples, 41 are npm (22 on 2026-09-27) and 6 are rpm — the npm ones under `/usr/lib/node_modules/{npm,nodemon}/node_modules`, which an image scan does not read (D70), the same gap as the SLES row. D117 bounds it: `maxGrypeOnlyApp.npm` is 82 for this target | assay ahead on OS packages; inventory gap on npm |
| RHEL 9 (ubi9) | 592 agree, 3 assay-only, 0 grype-only (ubi9) | not classified; the 3 assay-only are not examined | near parity |
| Debian 11 (end of support) | 211 agree, 5 assay-only, 0 grype-only (debian11) | added to the differential by D114 as an end-of-support target; the 5 are not classified | assay ahead, unclassified |
| Amazon Linux 2 (end of support) | 17 = 17, all agree (amazonlinux2) | added by D114 | exact parity |
| Photon OS | 22 = 22 (photon4), 42 = 42 (photon5), all agree | no one-sided tuples on either target | exact parity |
| Arch Linux | 9 agree, 2 assay-only, 0 grype-only (archlinux) | the 2 assay-only are not classified | assay ahead, unclassified |
| Mariner 2.0 | 134 agree, 53 assay-only, 0 grype-only (mariner2) | the 53 are not classified | assay ahead, unclassified |
| Bitnami (legacy postgresql) | 597 agree, 6 assay-only, 0 grype-only (bitnami-legacy-pg) | dual inventory (D99); the 6 are not classified | assay ahead, unclassified |
| Hummingbird | 32 agree, 7 assay-only, 31 grype-only (hummingbird) | neither side's extras are classified | bidirectional, unclassified |
| Alpaquita | 47 agree, 0 assay-only, 9 grype-only (alpaquita) | all 9 grype-only are grype's CPE fallback (`cpe-match` against `nvd:cpe`, no provider behind them) — the 2026-08-28 audit's classification, re-checked on the 2026-10-12 capture | exact parity on provider data |
| Liberica (BellSoft) | 61 agree, 0 assay-only, 29 grype-only (liberica21) | all 29 grype-only are grype's CPE fallback, as on Alpaquita (2026-08-28 audit, re-checked 2026-10-12). The 2026-10-12 run breached this target's `maxFindings` ceiling (≤56, got 61): +26 tuples since 2026-10-04, thirteen 2026 OpenSSL CVEs on `libcrypto3` and `libssl3` from BellSoft's feed, nothing removed, all 61 also reported by grype — benign upstream growth, re-banded | exact parity on provider data |
| CleanStart (postgres) | 0 agree, 0 assay-only, 101 grype-only (cleanstart-postgres) | 100 of grype's 101 are its CPE fallback on `apk` packages (2026-08-28 audit, re-checked 2026-10-12) — the matcher assay deliberately lacks; CleanStart's own feed reports nothing for this image, and a `minComponents` floor guards that the inventory is real. The 101st is `go-module` (`github.com/moby/sys/user` in `/usr/bin/gosu`): an in-image Go binary an image scan does not read (D70), bounded by D117's ceiling of 2 | parity on provider data; inventory gap on one Go binary |

The takeaway: most divergence was **data-source difference**, not matcher bugs, and the
one real bug the exercise found (the D90 CSAF ID collision) was fixed. Repeating this
measurement weekly is D93.

## Where policy differs

| Item | assay | grype | trivy | Context |
|---|---|---|---|---|
| CPE/NVD fallback matcher | none (deliberate) | yes | vendor-advisory-centric | Classified in the differential as grype's main false-positive class |
| FIPS/Ksplice/ESM lineages | reported not evaluated | judged against mainline data | no distinction | No verdict without the right data (D53, D79) — the Oracle differential confirmed this refusal is the correct side |
| Ignore rules | reason mandatory + expiry warns (D102) | yes | `.trivyignore` — a bare CVE list, no reason | Only assay refuses an unexplained waiver at load and shows every suppression in every output |
| VEX document input | OpenVEX files, `--vex` (D104) | yes | four methods (repo, file, OCI attestation, SBOM ref) | all three read OpenVEX files; trivy adds repo/attestation delivery. assay skips a reasonless `not_affected` with a warning where grype honours it silently, and resolves conflicting statements latest-first where grype takes the earliest |
| Multiple sources' ratings | all kept, gate takes the highest (D25) | single display | one source chosen by precedence | 8,893 of 19,715 CVE groups carry more than one record — assay shows the disagreement itself |
| Exit-code contract | `2 > 1 > 0` fixed (D11) | similar but not a stated contract | user-assigned via `--exit-code` | assay's "untrustworthy (2)" always outranks "findings (1)" — CI cannot confuse broken with clean |
| Flag names | same as grype where semantics match (D18) | — | its own scheme | For migration and scriptable differentials; silent divergence forbidden |

## assay-only

| Item | What it is |
|---|---|
| KISA/KNVD | Korean advisories as a first-class source; Korean prose enrichment via local `assay db build` |
| Every source's rating kept | When two databases rate one CVE differently, both are shown and the gate takes the highest (D25) — the report never disagrees with its own verdict |
| Seven gates + exit contract | `--fail-on`, `-unknown`, `-incomplete`, `-unfixable[=wont-fix]`, `-kev`, `-epss`, `-eol`, over exit `2 > 1 > 0` (D11) |
| Incompleteness carries a cause | Unevaluated packages are reported skipped with a count and a cause, never folded into a clean verdict; `--fail-on-incomplete=target` gates only what the caller can fix (D36) |

## Sources

The assay↔grype measurements and their per-family analysis live in
[deferred-decisions.md](deferred-decisions.md) (the 2026-08-24 differential entry and the
coverage-gap remeasure entry). The trivy column is from the
[trivy.dev documentation](https://trivy.dev/latest/docs/coverage/os/) as read on
2026-08-27. Decision IDs refer to the
[roadmap spec](superpowers/specs/2026-07-29-assay-roadmap.md).
