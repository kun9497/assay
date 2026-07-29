# assay

> **SBOM-driven vulnerability scanner for containers and filesystems.**

`assay` takes a software bill of materials — or generates one from a container image
or directory — and reports the known vulnerabilities affecting it.

```
  image / dir / SBOM  ──▶  package inventory  ──▶  vulnerability match  ──▶  verdict
```

---

## Status

🚧 **Early development.** The interfaces below are the design target, not a shipped feature set.
See [Roadmap](#roadmap) for what actually works today.

## Why another scanner?

Existing tools (grype, trivy) are excellent and battle-tested — use them in production.
`assay` exists to be **small and readable**: a scanner you can read end to end in an
afternoon and understand exactly how a package version becomes a CVE verdict. Matching
logic is the interesting part, and it is usually buried. Here it is the point.

Design goals, in order:

1. **Legible** — the match path is traceable without a debugger.
2. **Explainable** — every finding says *why* it matched, not just *that* it did.
3. **Offline-capable** — no network required at scan time once the DB is local.
4. **Boring output** — deterministic, diffable, CI-friendly.

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
# Scan an existing SBOM
assay scan sbom.cdx.json

# Scan a directory
assay scan dir:./my-project

# Scan a container image
assay scan alpine:3.19

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

## How it works

| Stage | Responsibility |
|-------|----------------|
| **Source** | Resolve the target into a package inventory (SBOM parse, or filesystem/image walk) |
| **Catalog** | Normalize packages into a common form — name, version, ecosystem, purl |
| **Database** | Local vulnerability store, refreshed out of band |
| **Matcher** | Per-ecosystem rules deciding whether a package version falls in a vulnerable range |
| **Report** | Render findings with the evidence that produced them |

The matcher is deliberately per-ecosystem. Version comparison is not universal —
Debian epochs, RPM release ordering, semver pre-release precedence, and Maven's
ordering rules all disagree with each other. A single "compare versions" function
is the bug factory that this design avoids.

## Roadmap

- [ ] CycloneDX SBOM ingestion
- [ ] SPDX SBOM ingestion
- [ ] Directory scanning (Go modules, npm, PyPI)
- [ ] Container image scanning
- [ ] Vulnerability database sync + local cache
- [ ] Per-ecosystem version comparison and range matching
- [ ] `--fail-on` severity gating
- [ ] JSON / SARIF / table output
- [ ] Explain mode — show the matching evidence for a single finding

## Contributing

Issues and PRs are welcome. This is a learning-oriented project, so **a PR that makes
the code clearer is as valuable as one that adds a feature.**

## Disclaimer

This is an independent personal project. It is not affiliated with, endorsed by, or
derived from any employer's product, and it carries no warranty of any kind. Do not
rely on it as your sole source of vulnerability information.

## License

[Apache License 2.0](LICENSE)
