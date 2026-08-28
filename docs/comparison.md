# assay · grype · trivy — a comparison

*Snapshot taken 2026-08-27, against assay v0.2.0, grype v6, and the trivy.dev
documentation as read that day. The assay↔grype numbers are **measured** — the same
digest-pinned images run through both scanners in the weekly differential (D93). The trivy
column is a **spec comparison** from its official documentation — trivy joined the weekly
differential in D105 (16 of the 23 targets, informational floors first), so measured
trivy numbers will accumulate from its first seeded run onward.*

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
| Language ecosystems | 8 | 8 | broader | The common eight (Go, npm, PyPI, crates.io, Maven, RubyGems, NuGet, Packagist); all three read pnpm and yarn berry lockfiles (assay since D103); trivy additionally covers Conan, Dart, Swift, Elixir |
| Enrichment gates | NVD · EPSS · KEV · EOL | NVD · EPSS · KEV · EOL | none built in | trivy is severity-centric; it does not gate on EPSS/KEV/EOL natively |
| KISA / KNVD | ✓ first-class | ✗ | ✗ | The reason assay exists rather than reusing an existing tool |
| Beyond vulnerabilities | ✗ (deliberate) | ✗ (deliberate) | misconfig · secrets · licenses | trivy is a multi-scanner — a different scope, not a gap |

## Measured parity — the 2026-08-24 differential (assay ↔ grype only)

The same digest-pinned images through both scanners, compared tuple by tuple. These 13
targets have since grown to 23 and run weekly in CI. trivy joined the run in D105 on the
16 targets it supports; its first measured floors are being seeded, so this table is
still assay↔grype only.

| Family | Result | Cause of divergence | Verdict |
|---|---|---|---|
| Alpine | 10/10 identical | grype's +4 are its CPE-fallback matcher — a thing assay deliberately lacks | exact parity |
| Ubuntu | 96/96, wont-fix 15/15 | Canonical-tracker fix states match exactly (D85) | exact parity |
| AlmaLinux | fixable set-equality | — | exact parity |
| Amazon · Wolfi | 0 = 0 | verified non-vacuous by downgrade probes | exact parity |
| Debian | 167 agreed | 6 assay-only tuples are grype DB gaps; 1 arguable assay FP (zlib1g/MiniZip) | assay ahead |
| Rocky | 99.4% on fixables | 2 assay-only tuples trace to a defective upstream record (RLSA-2023:6699, reported as peridot#204) | upstream defect |
| Oracle | — | grype-only tuples are FIPS-lineage ELSAs matched against mainline — assay's refusal (D79) is the correct side | assay ahead |
| Fedora | 30/30 at advisory level | CVE-extraction gaps are bidirectional — the Bodhi-prose limit (D75, 81.7%) | bidirectional gap |
| openSUSE Leap | — | grype v6 carries no Leap data at all | assay only |
| SLES (bci-base) | divergence both ways | data-model difference: assay expresses 108 affected-no-fix entries, grype carries LTSS-channel fixes — resolved by the D91 LTSS fold | resolved in D91 |

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
