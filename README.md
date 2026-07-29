# assay

> **SBOM-driven vulnerability scanner for containers, binaries, and filesystems.**

`assay` generates a software bill of materials from a container image, binary, or
directory — or ingests one you already have — and reports the known vulnerabilities
affecting it.

```
  image / binary / dir / SBOM  ──▶  package inventory  ──▶  vulnerability match  ──▶  verdict
```

---

## Status

🚧 **Early development.** The interfaces below are the design target, not a shipped feature set.
See [Roadmap](#roadmap) for what actually works today.

## Scope

`assay` covers the whole path in one tool: building the package inventory, building the
vulnerability database, and matching the two. In the anchore ecosystem those are three
separate projects — `syft`, `vunnel` + `grype-db`, and `grype`.

Existing scanners are excellent and battle-tested; use them in production. Two things
shape this one:

- **Korean advisory data.** KISA/KNVD publishes advisories and KVE identifiers covering
  software that NVD and OSV pick up late or not at all. Mainstream scanners do not ingest it.
- **Explainable matches.** Every finding carries the evidence that produced it — which
  range, which comparer, which comparison result — not just a verdict.

Design goals, in order:

1. **Explainable** — every finding says *why* it matched, not just *that* it did.
2. **Offline-capable** — no network required at scan time once the DB is local.
3. **Boring output** — deterministic, diffable, CI-friendly.

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

```bash
# Refresh the local vulnerability database (the only command that needs network)
assay db update

# Scan an existing SBOM
assay scan sbom.cdx.json

# Scan a directory
assay scan dir:./my-project

# Scan a container image
assay scan alpine:3.19

# Scan a binary
assay scan ./bin/assay

# Fail the build on high-severity findings
assay scan alpine:3.19 --fail-on high

# Machine-readable output
assay scan sbom.cdx.json --output json
```

### Exit codes

| Code | Meaning |
|-----:|---------|
| `0` | Scan completed; nothing at or above `--fail-on` |
| `1` | Scan completed; findings at or above `--fail-on` |
| `2` | Scan could not complete (bad input, DB error, etc.) |

Separating "found something" from "could not run" matters in CI — a broken scanner
should never look like a clean build.

## Architecture

The pipeline is five interfaces. Each is independently testable, and supporting a new
ecosystem means writing one `Cataloger` and one `Comparer` — nothing else changes.

| Interface | Responsibility | Implementations |
|---|---|---|
| `Source` | Open a target for file access; carries layer provenance | image, dir, file, binary |
| `Cataloger` | Files → `[]Package` | apk, dpkg, go-mod, go-binary, npm, jar |
| `Store` | `Lookup(ecosystem, name) []Advisory` | local vulnerability database |
| `Comparer` | `Compare(a, b string) int` | semver, PEP 440, apk, deb, rpm |
| `Provider` | Upstream feed → `[]Advisory` | OSV, KISA |

The database is orthogonal to the scan. `Provider`s populate it through `assay db update`;
a scan only ever reads. That is what makes offline operation the default rather than a flag.

Advisories are stored in **OSV shape** — `affected[].ranges[]` carrying `introduced` /
`fixed` events. OSV is the primary provider and passes through nearly unchanged; other
sources normalize into the same form. Choosing a proven normalization target beats
inventing one.

Two consequences worth stating up front, because both are easy to get wrong later:

- **Distro packages carry their release in the ecosystem key** — `Alpine:v3.19`, not
  `Alpine`. The fixed version of a package differs per release, so the release is part of
  the lookup key.
- **The distro belongs to the target, not the package.** An *image* is Alpine 3.19; its
  packages are not. `Target.Distro` is read from `/etc/os-release` once and applies to
  every OS package found inside.

### Why per-ecosystem version comparison

Version comparison is not universal — Debian epochs, RPM release ordering, semver
pre-release precedence, and Maven's ordering rules all disagree with each other. A single
`compareVersions` function is the bug factory this design avoids, and the reason
`Comparer` is per-ecosystem.

## Roadmap

Ordered by dependency — everything below builds on the core types and `Store`.

| | Stage | Contents |
|---|---|---|
| ① | **Core** | `Target` / `Package` / `Advisory` types, `Store`, `Matcher`, per-ecosystem `Comparer` |
| ② | **Database** | OSV ingestion, local store, `assay db update`, KISA enrichment |
| ③ | **Containers** | Registry pull, layer extraction, apk / dpkg catalogers |
| ④ | **Binaries** | Go `debug/buildinfo` first; other languages judged individually |
| ⑤ | **Reporting** | table / JSON / SARIF, `--fail-on`, explain mode |

- [ ] CycloneDX SBOM ingestion
- [ ] OSV provider and local vulnerability store
- [ ] Per-ecosystem version comparison and range matching
- [ ] KISA/KNVD enrichment — Korean descriptions, KVE aliases, severity
- [ ] Container image scanning (Alpine first, then Debian/Ubuntu)
- [ ] Go binary scanning via `debug/buildinfo`
- [ ] Directory scanning (Go modules, npm, PyPI)
- [ ] `--fail-on` severity gating
- [ ] JSON / SARIF / table output
- [ ] Explain mode — show the matching evidence for a single finding
- [ ] SPDX SBOM ingestion

Binary scanning depends entirely on what the language leaves behind. Go and Java embed
enough metadata to recover a dependency list; Rust does only when built with
`cargo-auditable`; stripped C/C++ leaves nothing reliable. Support is decided per language
rather than promised as a category.

## Contributing

Issues and PRs are welcome.

## Disclaimer

This is an independent personal project. It is not affiliated with, endorsed by, or
derived from any employer's product, and it carries no warranty of any kind. Do not
rely on it as your sole source of vulnerability information.

## License

[Apache License 2.0](LICENSE)
