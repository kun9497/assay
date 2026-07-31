# assay

> **SBOM-driven vulnerability scanner for containers, binaries, and filesystems.**

*English · [한국어](README.ko.md)*

`assay` generates a software bill of materials from a container image, binary, or
directory — or ingests one you already have — and reports the known vulnerabilities
affecting it.

```
  image / binary / dir / SBOM  ──▶  package inventory  ──▶  vulnerability match  ──▶  verdict
```

---

## Status

🚧 **Early development. Matching works; reading images does not yet.**

`assay db update` builds a local database from OSV, and `assay scan <file>.cdx.json` matches
a CycloneDX SBOM against it — Go, npm, PyPI, and **Alpine**. On real SBOMs it reports the
same findings as grype: same CVEs, not just the same count. See [Roadmap](#roadmap).

Alpine packages match through their *source* package, so an `openssl` advisory reaches the
installed `libssl3`, and the report names both. That indirection is where distro scanners
silently miss things.

Everything else below is still the design target, not the build. Concretely, `scan` takes
one CycloneDX file path and **accepts no flags**: container images, binaries, and
directories are not read directly — produce an SBOM with syft first — and neither
`--fail-on`, `--fail-on-unknown`, nor `--output json` exists. Exit code 1 is therefore
unreachable today: a completed scan exits 0 even when it reports findings.

[`docs/superpowers/specs/2026-07-29-assay-roadmap.md`](docs/superpowers/specs/2026-07-29-assay-roadmap.md)
carries the full design and the reasoning behind each decision.

## Scope

`assay` covers the whole path in one tool: building the package inventory, building the
vulnerability database, and matching the two. In the anchore ecosystem those are three
separate projects — `syft`, `vunnel` + `grype-db`, and `grype`.

Existing scanners are excellent and battle-tested; use them in production. Two things shape
this one:

- **Korean advisory data.** KISA/KNVD publishes advisories and KVE identifiers covering
  software that NVD and OSV pick up late or not at all. Mainstream scanners do not ingest it.
- **Explainable matches.** Every finding carries the evidence that produced it — which
  range, which comparer, which comparison result — not just a verdict.

Design goals, in order:

1. **Explainable** — every finding says *why* it matched, not just *that* it did.
2. **Offline-capable** — no network at scan time; `assay db update` is the only command
   that reaches out.
3. **Boring output** — deterministic, diffable, CI-friendly.

Configuration scanning, secret scanning, IaC, and Kubernetes posture are explicit
non-goals. They share almost no code with vulnerability matching.

## Install

```bash
go install github.com/kun9497/assay/cmd/assay@latest
```

Or build from source:

```bash
git clone https://github.com/kun9497/assay.git
cd assay
make build
```

## Usage

Working today:

```bash
# Build the local vulnerability database — the only command that needs network
assay db update

# What is in the database, and how current is it
assay db status

# Scan a CycloneDX SBOM (Go, npm, PyPI, Alpine)
assay scan sbom.cdx.json

# Container images are not read directly yet; produce the SBOM first
syft alpine:3.19 -o cyclonedx-json > alpine.cdx.json && assay scan alpine.cdx.json
```

Not implemented yet — listed so the target is unambiguous, not because it runs:

```bash
assay scan alpine:3.19                       # ② container images
assay scan ./bin/assay                       # ③ binaries
assay scan dir:./my-project                  # ③ directories
assay scan sbom.cdx.json --fail-on high      # ④ severity gating
assay scan sbom.cdx.json --fail-on-unknown   # ④ unrated findings
assay scan sbom.cdx.json --output json       # ④ machine-readable output
```

Flag names follow grype where the semantics match, so anything you already run against
grype should mean the same thing here. Where behaviour diverges it is documented rather than
left to be discovered — `--fail-on-unknown` is currently the only addition with no grype
equivalent.

### The database

Advisories are stored locally and refreshed out of band. A scan never downloads anything:
if the database is missing or its schema does not match, `assay` exits 2 and tells you to
run `assay db update` rather than silently fetching or silently reporting nothing.

| OS | Location |
|---|---|
| Windows | `%LocalAppData%\assay\db\v1\` |
| macOS | `~/Library/Caches/assay/db/v1/` |
| Linux | `~/.cache/assay/db/v1/` |

Override with `ASSAY_DB_DIR` for CI caching or air-gapped environments. The `v1` component
is the schema version — a schema change rebuilds into a new directory rather than migrating
in place.

A build over Go, npm, PyPI, and Alpine produces **64 MB on disk holding 32,050
advisories** — measured from an actual `db update`, not estimated. Getting there downloads
roughly 248 MB: OSV publishes one archive per ecosystem with no server-side filtering, and
most of npm's archive is malicious-package reports that are discarded on ingestion.

Alpine costs only 4 MB of that. OSV publishes it as one archive whose records carry
release-qualified ecosystem keys, so a single fetch covers every release from 3.2 to 3.24.

`assay db status` reports, per provider, when the **upstream data** was current — not when
you happened to download it. A mirror serving a three-month-old snapshot should not look
fresh just because it was fetched this morning.

### Exit codes

| Code | Meaning |
|-----:|---------|
| `0` | Scan completed; nothing tripped a gate |
| `1` | Scan completed; findings at or above `--fail-on`, or unrated findings with `--fail-on-unknown` |
| `2` | Scan could not complete, or its result cannot be trusted |

When more than one applies, **the highest wins**: `2` outranks `1` outranks `0`. An
untrustworthy result outranks the content of the result.

Separating "found something" from "could not run" matters in CI — a broken scanner should
never look like a clean build. Packages `assay` cannot evaluate are reported as skipped
with a count, never folded silently into a clean verdict.

## Architecture

The pipeline is five interfaces. Each is independently testable, and supporting a new
ecosystem means writing one `Cataloger` and one `Comparer` — nothing else changes.

| Interface | Responsibility | Implementations |
|---|---|---|
| `Source` | Open a target for file access; carries layer provenance | image, dir, file, binary |
| `Cataloger` | Files → `[]Package` | apk, dpkg, cyclonedx, go-mod, go-binary, npm, jar |
| `Store` | Advisory lookup | bbolt |
| `Comparer` | `Compare(a, b string) (int, error)` within one ecosystem | semver, PEP 440, apk, deb, rpm |
| `Provider` | Upstream feed → `[]Advisory` | OSV, KISA |

The database is orthogonal to the scan. `Provider`s populate it through `assay db update`;
a scan only ever reads. That is what makes offline operation the default rather than a flag.

Advisories are stored in **OSV shape** — `affected[].ranges[]` carrying `introduced` /
`fixed` events. OSV is the primary provider and passes through nearly unchanged; other
sources normalize into the same form. Reusing a proven normalization target beats inventing
one, and owning the schema is what lets KISA data in at all.

Records are stored **losslessly**, with derived values computed at query time — severity
bands come from stored CVSS vectors rather than being baked in at build time. Fields that
are not needed yet are stored anyway, because adding one later means rebuilding the
database.

Two things are dropped at ingestion. **Withdrawn advisories**, because a retracted advisory
that still produces findings is a plain false positive. And **malicious-package reports**
(`MAL-*`) — not because they matter less, but because they are a different finding class:
they carry no severity, name no fixed version, and call for "remove this and assume
compromise" rather than a severity band. They also account for roughly 80% of the raw data.
See [`docs/deferred-decisions.md`](docs/deferred-decisions.md) for what supporting them
properly would involve.

**Around half of all advisories carry no severity at all.** Coercing those to "low" would
turn a gap in the data into a passing build — exactly the failure the exit codes exist to
prevent. So `unknown` is its own band, outside the `low < medium < high < critical`
ordering rather than at the bottom of it:

- Unknown findings are **always reported**. A threshold decides what fails the build, never
  what appears in the output, and the unknown count is always in the summary.
- Unknown does **not** trip `--fail-on <band>` by itself. With half of all advisories
  unrated, the alternative would fire on every scan.
- `--fail-on-unknown` gates them **explicitly**, because the two rules above still let an
  unrated critical vulnerability exit 0 — printed, but passing.

### Three things that are easy to get wrong later

- **Distro packages carry their release in the ecosystem key** — `Alpine:v3.19`, not
  `Alpine`. The fixed version differs per release, so the release is part of the lookup key.
- **The distro belongs to the target, not the package.** An *image* is Alpine 3.19; its
  packages are not. `Target.Distro` is read from `/etc/os-release` once and applies to every
  OS package inside.
- **Packages carry their source package.** Distro advisories are written against *source*
  packages, but what is installed are *binary* packages — an advisory for source `openssl`
  will never be found by looking up `libssl1.1`. Missing this produces false *negatives*,
  which are silent. `Package.Source` exists for that lookup. This applies to Alpine as well
  as Debian and RHEL: Alpine's OSV records carry `?arch=source` in their purl.

### Why per-ecosystem version comparison

Version comparison is not universal — Debian epochs, RPM release ordering, semver
pre-release precedence, and Maven's ordering rules all disagree with each other. A single
`compareVersions` function is the bug factory this design avoids, and the reason `Comparer`
is per-ecosystem.

`Comparer` returns an error rather than only an ordering, because version strings from real
systems are sometimes malformed and treating an unparseable version as "not vulnerable"
would be a miss.

## Roadmap

Cut along working paths rather than architectural layers — a layer on its own cannot run,
and a design that cannot run cannot be validated.

**① Matching core** ✅ — CycloneDX SBOM → OSV-backed store → matcher → table output, for Go,
npm, and PyPI. Fixes the core types and interfaces.

- [x] Core types, `Store` / `Comparer` / `Provider` interfaces
- [x] OSV provider and local bbolt store
- [x] `assay db update`, `assay db status`
- [x] CycloneDX SBOM ingestion
- [x] Per-ecosystem version comparison and range matching
- [x] Table output

**②a Distro matching** ✅ — Alpine packages from an SBOM: release-qualified ecosystem
keys, source-package indirection, apk version ordering.

- [x] apk `Comparer`, checked against apk-tools' own 738-comparison test vectors
- [x] `Target.Distro` and the `Alpine:vX.Y` ecosystem key
- [x] `Package.Source` indirect matching
- [x] Alpine advisory ingestion

**②b Containers** — registry pull, layer extraction, whiteouts, `/etc/os-release`,
`/lib/apk/db/installed`. Everything above is a prerequisite: an image read perfectly but
matched against no distro ecosystem yields nothing.

- [ ] Container image scanning (Alpine first)

**③ Filesystem and binary targets** — depends on neither ② nor ④, so it can slot in
anywhere.

- [ ] Go binary scanning via `debug/buildinfo`
- [ ] Directory scanning (Go modules)

**④ Verdicts and output** — where exit code 1 first becomes reachable.

- [ ] `--fail-on` severity gating, plus `--fail-on-unknown` for unrated findings
- [ ] JSON / SARIF output
- [ ] Explain mode — show the matching evidence for a single finding

**⑤ KISA enrichment** — Korean descriptions, KVE aliases, and severity joined onto matched
findings.

- [ ] KNVD provider and enrichment join

Correctness is checked by **differential testing against grype** at every stage. Exact
agreement is not expected — the data sources differ — but a large divergence means the
matcher is wrong. Slice ① came out set-identical on both SBOMs it was run against:

| Target | assay | grype | missed | extra |
|---|---:|---:|---:|---:|
| PyPI SBOM (mixed-case names) | 32 | 32 | 0 | 0 |
| Go module SBOM | 4 | 4 | 0 | 0 |
| `alpine:3.19` SBOM | 10 | 10 | 0 | 0 |

Compared against grype's **distro-namespace** findings. Its `nvd:cpe` matches — 11 more on
the same image — come from CPE heuristics that `assay` does not implement, so folding them
in would flatter one tool or the other rather than compare them.

Five of the ten Alpine findings are only reachable through the source package:
`busybox-binsh`, `ssl_client`, and `musl-utils` carry advisories written against `busybox`
and `musl`. Without that indirection they are silent misses, which is why it is [D8].

Binary scanning depends entirely on what the language leaves behind. Go and Java embed
enough metadata to recover a dependency list; Rust does only when built with
`cargo-auditable`; stripped C/C++ leaves nothing reliable. Support is decided per language
rather than promised as a category.

Notable absences — Debian and RHEL support, VEX suppression, prebuilt database artifacts,
database age enforcement — are deliberate.
[`docs/deferred-decisions.md`](docs/deferred-decisions.md) records what was postponed, why,
what should trigger revisiting it, and which groundwork is already in place.

## Contributing

Issues and PRs are welcome. Before proposing a feature, check
[`docs/deferred-decisions.md`](docs/deferred-decisions.md) — the obvious gaps are mostly
deliberate, and it records what would change the decision.

## Disclaimer

This is an independent personal project. It is not affiliated with, endorsed by, or
derived from any employer's product, and it carries no warranty of any kind. Do not
rely on it as your sole source of vulnerability information.

## License

[Apache License 2.0](LICENSE)
