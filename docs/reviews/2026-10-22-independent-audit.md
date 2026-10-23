# Independent whole-source audit and service-readiness assessment — 2026-10-22

*English · [한국어](2026-10-22-independent-audit.ko.md)*

Run against `0164c94` (the D131 merge, the same commit the external review examined), in
parallel with the fixes of that review's six defects (PR #179, `docs/reviews/2026-10-22-source-review-response.md`).
The six were given to every agent as already known and excluded. **Nothing in this document
is fixed yet**; it is the list of what to fix next, with the evidence, in the order it should
be taken.

**Method.** Ten finder agents, one per subsystem, each in its own git worktree with the
instruction to read the subsystem whole, run its tests, and report only defects it could
reproduce (or honestly mark "not run"): source/image, OS catalogers, language catalogers and
SBOM readers, version comparers and range evaluation, matcher, OSV/NVD/EPSS/KEV providers,
CSAF/OVAL providers, store and `db` commands, scan verdict and renderers, CI/release/supply
chain. Every P1–P3 finding was then handed to two independent refuters — a correctness lens
(is it intended per the D decisions or a recorded deferral?) and a reproduction lens (does it
reproduce on the real call path?) — each told to default to "refuted" when unsure. A finding
is **confirmed** only when neither refuter could refute it. A separate agent assessed
service readiness from the documents and workflows. 51 agents, ~6.9M tokens, 67 minutes.

Result: **18 confirmed, 2 contested (one refuter each way), 0 refuted, 16 P4 reported
without verification.** The zero refutations say more about the finders' own bar than about
the refuters: finders were told to make the tests disprove a hypothesis before filing it.

**Status (2026-10-23).** A1 is fixed as D142.

## 1. Confirmed findings, by the order they should be fixed

Priority is the finders' and the refuters' agreed label (P1 = silent false negative on a
mainstream path; P2 = conditional wrong verdict or exit code; P3 = data-quality or robustness
defect with a visible symptom). Within a priority the order is mine: how many real targets it
reaches first, how cheap the fix is second.

| # | Pri | Where | Defect | Consequence | Evidence (reproduced) |
|---|---|---|---|---|---|
| A1 | P1 | `internal/matcher/matcher.go:441` | `ubuntuLineageMarker` is `[~+](esm\|fips)[0-9]`; Canonical's 16.04/18.04/20.04 FIPS builds are spelled `.fips.N` (`1.1.1f-1ubuntu2.fips.20`). The D53 skip never fires for them | dpkg orders `fips` above the empty string, so `…2.fips.12` sorts above the mainline fix `…2.18`: **0 findings, 0 skips** on a 20.04/18.04 FIPS host — the exact direction D53 was built to prevent | `ubuntuLineageOf("1.1.1f-1ubuntu2.fips.12") = ""`; `Compare(...fips.12, ...2.18) = 1`; matcher 0/0. Live OSV `UBUNTU-CVE-2024-0727` on `Ubuntu:Pro:FIPS-updates:20.04:LTS` |
| A2 | P1 | `internal/provider/oracle/oval.go:913` | `dropAmbiguous` drops every contributor of a (CVE, major, package, stream) group with more than one fixed EVR. D74/D79/D81 justify it as the kernel-UEK train guard, but 9,305 of 188,193 groups are non-kernel and **all 9,305 are totally ordered** by the RPM comparer — the ordinary "fixed in el9_5, re-fixed in el9_6" shape | openssh (CVE-2024-6387), glibc (CVE-2023-4911), openssl-libs, curl, sudo, bash and ~1,500 more Oracle Linux packages have **no record at all** for those CVEs | live 2026-10-22 archive measured: `non-kernel=9305 (distinct pkgs=1567, totally ordered=9305)`; `stored record for CVE-2025-2487 389-ds-base OL9: false` |
| A3 | P1 | `internal/cataloger/spdx/spdx.go:212` | Red Hat's own SPDX spells the binary→source link as a separate `?arch=src` package joined by `GENERATED_FROM`; binary purls carry no `upstream`. The reader takes Source only from `upstream` and skips the src package, so **every binary rpm in a Red Hat SBOM has `Source == nil`** | Red Hat's 1.29M no-fix entries are keyed on the source name and reachable only via `Source.Name`: a vendor SBOM scan reports `openssl-libs`, `krb5-libs`, `glibc-common`… **clean** where the image scan of the same content finds them | spdx probe `source=<nil>`; image path 1 finding (wont-fix) vs SPDX path 0 |
| A4 | P2 | `internal/cataloger/rpmdb/header.go:243` | `Source.Version` is filled with the **binary** EVR, not the SRPM's (`pkgmeta.SourceRPMVersion` exists and is unused). Fedora Bodhi, Photon and Azure Linux OVAL store source NVRs only | a subpackage whose epoch/version differs from its SRPM is compared across namespaces: Fedora `mod_ssl 1:2.4.x` from `httpd 2.4.x` is judged by the wrong counter (silent FN when above, FP when below: `perl-*`, `device-mapper-*`) | rpmdb probe `mod_ssl: Version="1:2.4.62-1.fc40" Source={httpd 1:2.4.62-1.fc40}`; matcher probe shows the wrong-counter verdict |
| A5 | P2 | `internal/provider/suse/csaf.go:917` | D91's LTSS tie-break discards the LTSS entry whenever a mainline entry for the same (key, package) exists, on the premise the shadow case is fix-vs-fix. Post-EOL documents keep the EOL'd product in `known_affected` (no fix) beside the LTSS `recommended` fix | an SLES 15 SP6-LTSS image with `php8-8.2.35-150600.3.39.1` (the fix) installed is reported **affected, no fix available**; 167 such shapes in the 400 most recent documents | probe over 400 docs: `167 LTSS FIXED, mainline NO-FIX -> fix lost` |
| A6 | P2 | `internal/cataloger/gemlock/gemlock.go:144` | `nokogiri (1.13.8-aarch64-linux)` keeps the platform suffix in the version; the Gem comparer reads the hyphen as a prerelease (`1.13.8.pre.aarch64…`, below 1.13.8) or refuses it on an underscore | native gems: an advisory introduced at the installed version yields **no finding and no skip**; one fixed there yields a false positive; `x86_64-linux` variants are skipped as unparseable | `Gem.Compare("1.13.8-arm64-darwin","1.13.8") = -1`; `"1.13.8-x86_64-linux"` → error |
| A7 | P2 | `internal/version/rangeeval.go:246` | `sortEvents` orders by version only; on an equal-version tie between one window's `fixed`/`last_affected` and another's `introduced`, file order wins, so an out-of-order range opens and closes a window at the same version | every version inside the second window is judged **clean** with empty Evidence; the same events sorted return affected (OSV does not require sorted events, and the project's own test says so) | probe: `v=2.0.5 sorted=true unsorted=false` for both `fixed` and `last_affected` |
| A8 | P2 | `.github/scanner-diff-targets.json:118,128` | `az2023` and `wolfi` floors are `minAgree 0 / minFindings 0`, left from the 2026-08-28 seeding; `comparison.md` records 83 and 12 agreements today | a candidate that loses **every** Amazon Linux 2023 or Wolfi match passes the D114 nightly gate and the weekly with `ok` — the D90 shape the gate exists for | scandiff run with zeroed matches: `az2023 0 83 0 … ok`, `wolfi 0 83 0 … ok`, exit 0 |
| A9 | P2 | `internal/scancmd/eol.go:140` | `st.EOL = now.After(eolDate)` with the date at 00:00 UTC makes a release EOL from the first nanosecond of the EOLFrom day; D87 and the field's own comment promise the boundary is exclusive (the day after) | `--fail-on-eol` goes red **one day early** (from 09:00 KST on the EOLFrom day); `eoesUnexpired` has the same shape | run: `exit=1`, `EOL: alpine 3.19 reached end of Security Support on 2026-01-01` on 2026-01-01T00:00:00Z |
| A10 | P3 | `internal/source/walk.go:323` | a non-regular entry (directory, device, FIFO) at a wanted path in an upper layer neither answers nor closes the query; `hiddenFrom` matches only `<name>/` prefixes, so a file→directory replacement (`<name>/` + `<name>/.wh..wh..opq`, no `.wh.<name>`) does not hide `<name>` | the deleted lower layer's package database or `os-release` is read: a **stale inventory** with no symptom. Same gap in `FilesUnder/Named/Matching`. Rare shape for the paths assay asks for | probe: `present=true data="OLD-DB" diff=sha256:base` for TypeDir, TypeChar, TypeBlock, TypeFifo |
| A11 | P3 | `internal/pkgmeta/distro.go:684` | Alpine edge's real `VERSION_ID` is `3.21.0_alpha20240807`; the fallthrough cuts at the first two dots and keys it as `Alpine:v3.21`. The refusal test spells it `3.21_alpha…`, which edge never writes | an `alpine:edge` image is judged against a stable release's advisories instead of being refused | probe keys to `Alpine:v3.21` |
| A12 | P3 | `internal/cataloger/gobinary/goversion.go:59` | a binary built with a non-default `GOEXPERIMENT` is stamped `go1.26.7-X:fieldtrack` (hyphen, release toolchains); the normaliser takes the suffix as a semver prerelease | stdlib is cataloged as `1.26.7-X:fieldtrack`, which the comparer refuses: every stdlib advisory becomes a skip rather than a verdict | probe shows the cataloged version and the skip |
| A13 | P3 | `internal/matcher/matcher.go:1289` | `absorb()` moves the absorbed group's winner (`Advisory`, `Evidence`, `MatchedName`, severity) but not `CrossMappedFrom`, `MatchedViaProvides`, `FrozenSince`; the `beats()` swap carries all three | a merged finding discloses the wrong join or mirror origin — a D10 explainability defect, not a verdict change | probe shows the mismatch after a merge |
| A14 | P3 | `internal/provider/nvd/parse.go:78` | a record carrying only a CVSS v2 vector is stored (`CVSS_V2`) but `severity.Of` scores only `CVSS:3.`/`CVSS:4.` | every pre-Dec-2015 CVE NVD never re-scored joins the NVD source and still reports `unknown` — counted as rated, banded as nothing | probe: `severity.Highest` on the v2-only rating = Unknown/0 |
| A15 | P3 | `internal/provider/osv/ubuntu_fixstate.go:207` | a tracker clone that parses to zero tuples (layout change, header respelling) is accepted with a progress line; nothing fails the build or the publish guard | every Ubuntu wont-fix/not-fixed state silently disappears from an artifact | probe: empty tracker → `stamped 0`, build continues |
| A16 | P3 | `internal/report/sarif.go:89` | SARIF `not-evaluated` results come only from the matcher's skips; components the **cataloger** could not turn into packages (no PURL, no version, unsupported ecosystem, damaged rpm headers) produce no result | GitHub code scanning sees a clean scan where the table says N not evaluated | SARIF of such a scan: no `assay/not-evaluated` result, only the invocation notification |
| A17 | P3 | `cmd/scandiff/normalize.go:66` | scandiff reads `summary.notEvaluated` only; `incompleteChecks` and `targetIncomplete` are not read | a candidate database whose bounds stopped parsing (every check incomplete) is judged trustworthy by the gate | normalize.go reads three fields; run.go feeds one |
| A18 | P3 | `.github/actions/setup-scanners/action.yml:38` + `deferred-decisions.md` "Signing" | the signing deferral's revisit trigger ("the moment a third party's `db update` trusts this registry by default") fired on 2026-08-28 when the package went public and `DefaultRef` started trusting it; the publish job runs an unpinned `curl \| sh` installer and tag-pinned actions beside `packages: write` | the artifact every customer pulls is unsigned, and the job that pushes it executes third-party code pinned by mutable tag | workflow text; `pull.go:25` |

**Contested (one refuter each way):**

| | Where | Claim | The disagreement |
|---|---|---|---|
| B1 | `internal/cataloger/cyclonedx/cyclonedx.go:173` | syft spells the Go toolchain `pkg:golang/stdlib@go1.21.0`; neither SBOM reader normalises it, so stdlib is skipped as unreadable and the scan is target-incomplete | the correctness refuter calls it a real P2 gap (gobinary normalises the same string); the reproduction refuter rates it P4 because the skip is visible and `--fail-on-incomplete=target` trips on it — loud, not silent |
| B2 | `internal/provider/suse/csaf.go:483` | a bare `known_affected` id whose product_version leaf is absent is dropped (`skipUnknownPackage`) although D126 names bare ids by product_id anyway; 503 sole "affected, no fix" statements lost in 400 recent documents (SLES 15 SP7, 16.0) | one refuter sees a D126 follow-through that loses data for no information; the other calls the leaf requirement the documented guard against mis-keyed ids and rates it P4 pending a measured false-positive count if relaxed |

**P4, reported without verification** (worth a look, not evidence): duplicate paths inside
one layer tar (first wins, extraction gives last); a symlink chain past 8 hops is silently
absent; D119's arm64→arm non-fallback vs containerd's `platforms.Only`; `alpine:edge` keying
(the P3 above, filed twice); lockfile git/fork dependencies cataloged by the fork's declared
version; `requirements.txt` packages carry no PURL/Type/Location (VEX cannot reach them);
apk comparer on all-zero dotted components of unequal length; an unorderable bound blamed on
the package (`CauseTargetVersion`); first-hit Evidence naming the wrong range; NVD 403
rate-limit responses classified permanent; SUSE `SkippedNoPurl` counted but never printed;
`--ratings-only` dropping the seed's EOL catalog when no EOL source is configured;
`--explain` on a waived finding answering "no finding"; table headline "No known
vulnerabilities" when every finding was waived; the SUSE `upstreamvectors` test absent from
CI; the weekly differential's fail step lacking the nightly's fail-closed fallback.

## 2. Service-readiness assessment

The readiness agent read `CLAUDE.md`, `README.md`, `docs/DESIGN.md`, `docs/deferred-decisions.md`,
`docs/comparison.md`, `docs/integrations.md`, the roadmap's D28/D58/D59/D110/D114/D120, all
five workflows, the release configuration and installer, and the pull/scan code paths. Its
bottom line, which I share after reading the evidence it cites: **the scanning core is
unusually well-verified for a three-month-old project, and the published-artifact pipeline
has more self-checks than most commercial scanners expose; it is not sellable today for
reasons that are mostly around the code.** The five gaps, each with the cheapest credible
remedy the agent proposed:

1. **Nothing is signed and nobody can verify who built the database.** Binaries ship with
   sha256 checksums only (no cosign, no SLSA provenance, no SBOM); the artifact is
   digest-verified on pull but unsigned, and the deferral's own revisit trigger has fired
   (A18); `install.sh` is an unpinned `curl | sh` from `main`; no `dependabot.yml`, no
   `SECURITY.md`. Remedy: cosign keyless in `release.yml` and after `db push` in
   `db-publish.yml`; a `cosign.Verify` step in `pull.go` exiting 2 on failure (with an
   explicit skip for air-gapped mirrors); pin the installer to a tag; add dependabot and a
   security policy.
2. **Nothing pages anyone, and manual steps sit on the critical path.** No notification step
   in any workflow (two nightlies failed silently on 2026-08-04/05); the schema-bump bootstrap
   is a hand-run local build and push; Monday re-banding is manual; the registry lives under a
   personal namespace; `db update` has no retry or fallback and a customer sees only an aging
   date. Remedy: an `if: failure()` step that opens or updates a pinned issue or posts to a
   webhook; a published `status.json` (last good digest, data-as-of, gate result); the
   bootstrap as a `workflow_dispatch` job; a default stderr warning when advisory data is older
   than seven days; a three-attempt retry in `Pull`; an org namespace.
3. **In-image application packages are silently absent (D70).** Exit 0, zero findings, no
   disclosure in table or SARIF; measured Criticals missed on three differential targets.
   Remedy: ship the deferral's own "S" option now (one stderr line and a SARIF
   `assay/inventory-scope` notification on every image scan), then the fixed-location probe
   the entry already sizes.
4. **The differentiator cannot be delivered as a service.** D29 strips KISA from every
   artifact; a customer wanting the Korean prose must run the multi-hour `db build` with `git`
   and every upstream reachable. Remedy: resolve the licence (a business action), failing that
   a `db build --enrichment-only --seed <ref>` that seeds advisories and ratings verbatim and
   fetches only KNVD (minutes, no `git`).
5. **Verification has holes where the project's own rules say holes form.** The SUSE
   live-feed test is tagged `upstreamvectors` and never run by CI (the "counted as coverage,
   never executes" shape `ci.yml` warns about); CI is `ubuntu-latest` only, so the
   Windows-tagged tests never run; `comparison.md` carries unclassified assay-only tuples
   (wolfi 34, mariner2 53, ubuntu 38) that are candidate false positives shipping to customers;
   the gate is regressions-only by design. Remedy: add the SUSE tag run to CI; a
   `windows-latest`/`macos-latest` matrix leg without `-race`; a classification job and a
   `maxAssayOnly` ceiling per target so FP growth trips the weekly run the way grype-only
   growth does since D117.

Cheap items the agent lists before a first customer: `cmd/assay/main.go` usage and
`DESIGN.md` §Usage are stale (still "go.mod alone", "Go, npm, PyPI, Alpine"); `DESIGN.md:75-76`
still says "a personal project — use existing scanners in production"; no `CHANGELOG.md`,
`SECURITY.md`, `CONTRIBUTING.md` or JSON-schema compatibility statement (`schemaVersion` went
10→14 in three weeks); `db status` has no `--output json` and `db` ignores unknown flags; the
installer has no Windows path; the documented CI cache key survives an upgrade.

What a customer must be told today (the agent's §6, which matches the deferral record): D70
application packages; frozen end-of-support data (Debian 11); Ubuntu ESM/FIPS and Oracle
Ksplice/FIPS not evaluated and RHEL EUS/AUS/E4S judged against mainline; no KISA in the
artifact; no CPE/NVD fallback matcher; one platform per run, no Docker daemon source, SBOMs
without `syft:distro:*` leave OS packages unmatched; eight language ecosystems; `MAL-*`
excluded.

## 3. Assessment and recommended order

**On the audit.** Three P1s are silent false negatives on mainstream inputs and should go
first, in this order: A1 (one regex and a measurement of Canonical's spellings — hours), A3
(read `GENERATED_FROM` in the SPDX reader — a day), A2 (replace the blanket ambiguity drop
with "drop only when the group is not totally ordered, else keep the highest" — a day plus a
re-measurement on the live archive and a differential run, since it adds records to Oracle
Linux). Then the P2s that change verdicts on real targets: A5 (SUSE LTSS, 167 shapes in 400
documents), A4 (rpm SRPM version, which the Fedora/Photon/Azure keys depend on), A7 (a
tie-break in `sortEvents`, small and dangerous), A6 (gem platform suffix), A8 and A17 (gate
floors and the scandiff summary read — cheapest of all, and they protect everything else),
A9 (one comparison). The P3s are a release's worth of smaller work; A18 is the first item of
the readiness list below. Each fix should follow the same discipline as the six in PR #179:
a failing test on the real call path, the fix, a mutation round, bilingual documentation,
and a measurement on the live data where the finding quotes one.

**On readiness.** I agree with the agent's bottom line. The code is in better shape than the
operation around it. Before offering this as a paid service I would do, in order: (1) signing
of both the binary and the artifact plus a verifying pull (gap 1, which also closes A18);
(2) failure notification and a public freshness signal (gap 2); (3) the D70 disclosure line on
every image scan, so the largest known blind spot is loud (gap 3); (4) the three P1s above;
(5) the CI holes (gap 5) and the gate floors (A8, A17); (6) the documentation items, which are
cheap and are what a customer reads first. The KISA question (gap 4) is a business decision
that gates the product's stated differentiator and should be settled in parallel.

Everything above is a proposal. Nothing in this document has been changed in the code.

## Re-running

The per-agent transcripts and each finding's reproduction are in the workflow journal
(`wf_fbadf3f4-a84`, local to the session that ran it). Every confirmed row's "Evidence"
column quotes the probe output the refuters observed; the probes were throwaway tests written
against `0164c94` in isolated worktrees and are reproducible from the row's own description.
