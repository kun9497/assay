# assay

> **Vulnerability scanner for containers, binaries, and filesystems.**

*English · [한국어](README.ko.md)*

`assay` generates a software bill of materials from a container image, binary, or
directory — or ingests one you already have — and reports the known vulnerabilities
affecting it.

```
  image / binary / dir / SBOM  ──▶  package inventory  ──▶  vulnerability match  ──▶  verdict
```

---

## Status

🚧 **Early development. Alpine containers scan end to end; other distros do not.**

`assay db update` builds a local database from OSV, and `assay scan` matches against it —
Go, npm, PyPI, and **Alpine**. It reads container images directly, so syft is no longer in
the loop. On real targets it reports the same findings as grype: same CVEs, not just the
same count. See [Roadmap](#roadmap).

Alpine packages match through their *source* package, so an `openssl` advisory reaches the
installed `libssl3`, and the report names both. That indirection is where distro scanners
silently miss things.

Go **binaries** and **directories** are read too — `debug/buildinfo` for the former,
`go.mod` for the latter, with the Go toolchain itself matched as the package `stdlib`.

Findings carry a severity band derived from the stored CVSS vector, and `--fail-on`,
`--fail-on-unknown` and `--fail-on-incomplete` turn that into an exit code CI can gate on.
`--output json` gives a stable machine-readable document and `--explain <id>` prints why a
single finding matched.

A finding keeps **every** database's rating rather than the first one matched, and the
verdict is the highest band across them. On a real Django 3.2.12 scan that is 15 of 19
findings described by two sources, 14 of which only one of the two rated at all — so before
this, 14 verdicts turned on which record the package index happened to list first.

Everything else below is still the design target, not the build. Non-Alpine images are read,
but their packages cannot be matched: `assay scan debian:12` reports that it found no
supported package database and exits 2, rather than reporting a clean image it never
checked.

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
2. **Offline-capable** — a scan never fetches vulnerability data, and a scan of anything
   already on disk makes no network call at all. Only a remote *target* is fetched, and
   only when you name one: `assay scan alpine:3.19` reaches out, `assay scan
   docker-archive:alpine.tar` does not.
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
# Build the local vulnerability database — the only command that fetches advisories
assay db update

# What is in the database, and how current is it
assay db status

# Scan a container image from a registry
assay scan alpine:3.19

# ...or one you already have on disk. Neither of these touches the network.
docker save alpine:3.19 -o alpine.tar && assay scan docker-archive:alpine.tar
skopeo copy docker://alpine:3.19 oci:layout && assay scan oci-dir:layout

# Scan a CycloneDX SBOM (Go, npm, PyPI, Alpine)
assay scan sbom.cdx.json
```

### What a target can be

```bash
assay scan alpine:3.19                # a registry reference
assay scan docker-archive:app.tar     # a `docker save` tarball
assay scan oci-dir:./layout           # an OCI layout directory
assay scan sbom.cdx.json              # a CycloneDX SBOM
assay scan ./bin/assay                # a Go binary
assay scan ./my-project               # a directory with a go.mod
```

A bare path is classified by **content**: a directory if it is one, a Go binary if
`debug/buildinfo` can read it, a CycloneDX document if it has a top-level `bomFormat`. A file
that is none of those is an error naming all three, never a silent guess. Anything that is
not a path at all is a registry reference.

The prefixes `file:`, `dir:` and `sbom:` override the sniff, alongside `docker-archive:` and
`oci-dir:`. Every scan prints how it classified the target on stderr, so a wrong guess is
visible in the output rather than inferred from a confusing parse error.

*On Git Bash for Windows, a prefixed absolute path is not translated —* `dir:/c/project`
*reaches the program as* `\c\project`. *Use a relative path, or a native one:*
`dir:C:/project`.

### Binaries and directories

A **binary** scan reads `debug/buildinfo`: the main module, every dependency the linker
actually kept, and the toolchain — matched as the package `stdlib`, which the Go
vulnerability database holds 159 advisories against.

A **directory** scan parses `go.mod`, with the standard library and no `go` invocation, so it
works offline and needs no toolchain. That means it reports what the module *requires*, which
is not what a build links. On this repository:

| | packages |
|---|---|
| the built binary | **12** — main module, 10 linked dependencies, `stdlib` |
| `go.mod` | **11** — including `gotest.tools/v3`, which no build links |
| `go list -m all` | **52** — the whole module graph |

The difference is named in the scan's own output, and it is why a directory scan says so:

```
$ assay scan dir:.
scanned dir:. as a directory
go.mod names 11 module(s); this is what was requested, not what a build links
  - scan the built binary for that
```

Scan the binary for what ships. The reasoning is recorded as D23.

Not implemented yet — listed so the target is unambiguous, not because it runs:

```bash
assay scan dir:./node-project                # ③ npm and PyPI directories
```

### Verdicts

```bash
assay scan alpine:3.19 --fail-on high         # exit 1 on a high or critical finding
assay scan alpine:3.19 --fail-on-unknown      # exit 1 on an unrated finding
assay scan alpine:3.19 --fail-on-incomplete   # exit 2 if anything went unevaluated
assay scan alpine:3.19 --output json          # one JSON document on stdout
assay scan alpine:3.19 --explain CVE-2025-46394
```

`--fail-on` takes `none`, `low`, `medium`, `high` or `critical`. Bands come from the stored
CVSS vector at query time, so a scoring correction ships as a code change rather than a
database rebuild. Both CVSS v3.1 and v4.0 are scored; v4 needs a 270-entry lookup table and
an interpolation step rather than a formula, and both scorers are checked against every
vector in the live database.

`--fail-on-incomplete` exits **2**, not 1, and it beats `--fail-on` when both apply: a
result that cannot be trusted outranks the content of the result. It fires when packages
were never checked *or* when a check could not be completed — the same pair of counts the
report always discloses, in the summary line and under "Not evaluated", so the gate can
never fire over something the output did not show you.

Flag names follow grype where the semantics match, so anything you already run against
grype should mean the same thing here. Where behaviour diverges it is documented rather than
left to be discovered:

| | grype | assay |
|---|---|---|
| lowest band | `negligible` | `none` |
| unrated findings | fold into the ordering | `unknown`, outside it — `--fail-on-unknown` only |
| partial coverage | no gate | `--fail-on-incomplete`, exit 2 |
| explain | `grype explain` subcommand | `--explain <id>` flag on `scan` |
| severity source | enriched from NVD via the CVE alias | the stored CVSS vector only (D13) |

The severity divergence is the one worth knowing about. Measured on this repository's own
binary: assay and grype find **the same three findings** — same packages, same advisory IDs,
same fixed versions — but grype rates two of them High and Medium where assay says `unknown`.
Neither is wrong. All three advisories carry **zero** severity entries in the OSV data, so
`unknown` is what D13 and D17 require; grype reaches NVD through each advisory's CVE alias
and finds a score there. Enriching from NVD is a recorded deferral, not a plan — the mechanism for it landed with
D25, the cost is CPE-to-purl matching, and `docs/deferred-decisions.md` names the trigger.


`--explain` matches on the advisory's own ID or any alias, so the CVE you were given
resolves even when the record is filed under a GHSA or a distro-prefixed ID.

Two databases routinely describe the same vulnerability and disagree about it. Measured
against the live database: of 19,715 vulnerability groups, 8,893 (45%) carry more than one
record, and in 5,693 of those the sources land on different severity bands (D25). A real scan of
Django 3.2.12 finds 19 vulnerabilities, 15 of them described by both GHSA and PYSEC, and 14
of those 15 rated by only one of the two. A finding
keeps every source's rating rather than discarding all but one, and the gate uses the
highest band across them — an `unknown` from one source never dilutes a `critical` another
source gave (D17). The table stays one row per finding, but marks the SEVERITY cell with `*`
when its sources land on different bands, with a footnote pointing at `--explain <id>` for
the detail; `--output json` carries every source in a `ratings` array rather than collapsing
to the one that won.

### The database

Advisories are stored locally and refreshed out of band. A scan never downloads anything:
if the database is missing or its schema does not match, `assay` exits 2 and tells you to
run `assay db update` rather than silently fetching or silently reporting nothing.

| OS | Location |
|---|---|
| Windows | `%LocalAppData%\assay\db\v5\` |
| macOS | `~/Library/Caches/assay/db/v5/` |
| Linux | `~/.cache/assay/db/v5/` |

Override with `ASSAY_DB_DIR` for CI caching or air-gapped environments. The `v5` component
is the schema version — a schema change rebuilds into a new directory rather than migrating
in place. Note that `ASSAY_DB_DIR` carries no such component, so a CI cache keyed on that
path survives an upgrade that should have invalidated it. Rebuild after upgrading, or key
the cache on the assay version.

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
| `2` | Scan could not complete, or its result cannot be trusted — including `--fail-on-incomplete` |

When more than one applies, **the highest wins**: `2` outranks `1` outranks `0`. An
untrustworthy result outranks the content of the result.

Separating "found something" from "could not run" matters in CI — a broken scanner should
never look like a clean build. Packages `assay` cannot evaluate are reported as skipped
with a count, never folded silently into a clean verdict.

## Architecture

The pipeline is five interfaces. Each is independently testable, and supporting a new
ecosystem means writing one `Cataloger` and one `Comparer` — nothing else changes.

**Bold is built; the rest is the design target.**

| Interface | Responsibility | Implementations |
|---|---|---|
| `Source` | Open a target for file access; carries layer provenance | **registry**, **`docker save` tarball**, **OCI layout**, dir, binary |
| `Cataloger` | Files → `[]Package` | **apk**, **os-release**, **cyclonedx**, dpkg, go-mod, go-binary, npm, jar |
| `Store` | Advisory lookup | **bbolt** |
| `Comparer` | `Compare(a, b string) (int, error)` within one ecosystem | **semver**, **PEP 440**, **apk**, deb, rpm |
| `Provider` | Upstream feed → `[]Advisory` | **OSV**, KISA |

The database is orthogonal to the scan. `Provider`s populate it through `assay db update`;
a scan only ever reads, and never repairs a stale or missing one behind your back. That is
what makes offline operation the default rather than a flag — a scanner that quietly
downloads advisories produces results you cannot reproduce or audit.

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

**②b Containers** ✅ — registry pull, layer extraction, whiteouts, `/etc/os-release`,
`/lib/apk/db/installed`.

- [x] Images from a registry, a `docker save` tarball, or an OCI layout
- [x] Layer walking with whiteout and symlink resolution
- [x] `/etc/os-release` and `/lib/apk/db/installed` catalogers

The Docker daemon is deliberately not a source: importing it takes the linked dependency
count from 9 modules to 27, and an image already present locally reaches `assay` through
`docker save`.

**③ Filesystem and binary targets** — depends on neither ② nor ④, so it can slot in
anywhere.

- [x] Go binary scanning via `debug/buildinfo`, including the toolchain as `stdlib`
- [x] Directory scanning (Go modules, `go.mod` only — no toolchain, no network)
- [ ] npm and PyPI directory scanning

**④ Verdicts and output** — where exit code 1 first becomes reachable. **Done.**

- [x] `--fail-on` severity gating, plus `--fail-on-unknown` and `--fail-on-incomplete`
- [x] CVSS v3.1 and v4.0 scoring, checked against every vector in the live database
- [x] JSON output with a schema version and a golden-file test
- [x] Explain mode — show the matching evidence for a single finding
- [x] Per-source ratings — a finding keeps every database's assessment, the gate takes the
      highest (D25)
- [ ] SARIF output (see `docs/deferred-decisions.md`)
- [ ] NVD as a second rating source (see `docs/deferred-decisions.md`)

**⑤ KISA enrichment** — Korean descriptions and severity joined onto matched findings.
**On hold: investigated 2026-08-02 and the data does not support it.**

KNVD publishes **173** vulnerability records in total, and every one of the ten most recent
describes Korean domestic commercial software — ipTIME routers, 한컴오피스, 알집, a DVR, a
groupware suite. None is a Go, npm, PyPI or Alpine package, so a CVE-ID join against a
container image or a source tree would essentially never fire. The records themselves are
well-formed — CVE ID, CVSS score and band, affected and fixed versions, a Korean description
— so the obstacle is subject matter, not format. Access and licensing are also unfavourable:
the two documented RSS feeds return only the latest 10 items, and the site is marked
all-rights-reserved with no 공공누리 licence. Full findings in the roadmap.

- [ ] KNVD provider and enrichment join — revisit if targets expand to hosts or workstations

Correctness is checked by **differential testing against grype** at every stage. Exact
agreement is not expected — the data sources differ — but a large divergence means the
matcher is wrong. Slice ① came out set-identical on both SBOMs it was run against:

| Target | assay | grype | missed | extra |
|---|---:|---:|---:|---:|
| PyPI SBOM (mixed-case names) | 32 | 32 | 0 | 0 |
| Go module SBOM | 4 | 4 | 0 | 0 |
| `alpine:3.19` SBOM | 10 | 10 | 0 | 0 |

Reading the image directly is checked against the SBOM path rather than against grype,
because that comparison holds the database, matcher, and comparer fixed — any divergence is
ours alone. All four routes to the same image agree exactly:

| Route | findings |
|---|---:|
| syft SBOM | 10 |
| registry pull | 10 |
| `docker save` tarball | 10 |
| OCI layout directory | 10 |

The component totals differ by one, legitimately: syft emits an `operating-system`
component that the SBOM path counts and excludes, and reading the image directly produces
no such entry.

Compared against grype's **distro-namespace** findings. Its `nvd:cpe` matches — 11 more on
the same image — come from CPE heuristics that `assay` does not implement, so folding them
in would flatter one tool or the other rather than compare them.

Six of the ten Alpine findings are only reachable through the source package:
`busybox-binsh`, `ssl_client`, and `musl-utils` carry advisories written against `busybox`
and `musl`. Without that indirection more than half the findings are silent misses, which
is why it is [D8].

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
