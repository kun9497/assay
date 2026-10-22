# assay

> **A vulnerability scanner for containers, binaries, and filesystems — with KISA/KNVD Korean advisory data as a first-class source.**

*English · [한국어](README.ko.md)*

[![CI](https://github.com/kun9497/assay/actions/workflows/ci.yml/badge.svg)](https://github.com/kun9497/assay/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/kun9497/assay?sort=semver)](https://github.com/kun9497/assay/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/kun9497/assay.svg)](https://pkg.go.dev/github.com/kun9497/assay)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

`assay` builds a package inventory from an image, binary, directory, or SBOM, matches it
against a vulnerability database it manages itself, and returns a verdict your CI can gate
on. It covers the whole path in one tool — inventory, database, and match — where the
anchore ecosystem needs three (`syft` + `vunnel`/`grype-db` + `grype`). KISA/KNVD Korean
advisory data is the reason it exists rather than reusing grype.

<p align="center">
  <img src="docs/assets/demo.svg" alt="assay scan alpine:3.19 — real output" width="820">
</p>

## Install

```bash
# Prebuilt binary (Linux/macOS, amd64/arm64) — onto your PATH
curl -sSfL https://raw.githubusercontent.com/kun9497/assay/6221badd9bdb65e22cc99e842803a557c721e756/install.sh | sudo sh -s -- -b /usr/local/bin
```

The script embeds the project's signing key and verifies the release's checksums
signature with `openssl` (or `cosign`) before the checksum, then picks the right asset for
your OS/arch. The line names the commit the latest release was built from — never a branch
or a tag, which can move — and the release job updates it. Without `-b` it installs to
`./bin` (no sudo needed — add it to your PATH yourself); `-s -- vX.Y.Z` installs another
release, verified against the same keys. A release whose checksums file carries no
signature is refused, never installed on the checksum alone: v0.10.0 is the first signed
release, so anything older goes through `go install` or the release page.

<details>
<summary>Other ways to install</summary>

```bash
# With Go
go install github.com/kun9497/assay/cmd/assay@latest

# From source
git clone https://github.com/kun9497/assay.git && cd assay && make build   # -> bin/assay
```

Prebuilt binaries and checksums for every platform are attached to each
[release](https://github.com/kun9497/assay/releases/latest).
</details>

## Quick start

```bash
# 1. Get the vulnerability database (seconds — pulls the published OCI artifact and
#    verifies its signature against the key built into assay)
assay db update

# 2. Scan something
assay scan alpine:3.19                    # a registry image
assay scan --platform linux/arm64 alpine:3.19   # another platform of a multi-platform image
ASSAY_REGISTRY_AUTH_TOKEN=$TOKEN assay scan registry.example.com/team/app:1.0   # a private registry
assay scan docker-archive:image.tar       # a local tarball — no network
assay scan sbom.cdx.json                  # a CycloneDX or SPDX SBOM
assay scan ./my-service                   # a Go binary, or a directory with lockfiles

# 3. Gate CI on it — exit 1 at or above the threshold, exit 2 if the scan can't be trusted
assay scan alpine:3.19 --fail-on high
```

`assay scan` writes results to stdout and diagnostics to stderr, so
`assay scan … --output json | jq` stays clean. `--output` also does `sarif` (for GitHub
code scanning) and `table` (the default). `--explain` shows one finding's full evidence.

**Private registries.** Scanning a registry image tries, in order:
`ASSAY_REGISTRY_AUTH_USERNAME` + `ASSAY_REGISTRY_AUTH_PASSWORD` (or
`ASSAY_REGISTRY_AUTH_TOKEN`), then your `docker login` (`DOCKER_CONFIG` or
`~/.docker/config.json`, credential helpers included), then podman's (`REGISTRY_AUTH_FILE` or
`$XDG_RUNTIME_DIR/containers/auth.json`). The environment credential is offered only to the
target's own registry unless `ASSAY_REGISTRY_AUTH_AUTHORITY` names another; a half-set one is
exit 2, and values are never printed. `--platform os/arch[/variant]` picks a platform; the default
is this host's, chosen as the container runtime would, and the scanned platform and digest are
printed on stderr and recorded in the JSON `image` object.

**What produced a verdict.** Every JSON and SARIF report carries a `provenance` object — the
assay build, the database (and the published artifact digest `db update` pulled), the target's
content hash, every gate flag, and each ignore rule and VEX document with its hash and how
many findings it matched — with no timestamp, so the same inputs still produce the same
bytes. `--provenance <path>` also writes a sidecar with the run's start and finish time, exit
code and the report's sha256, even when the scan ends in exit 2 before any report exists.

## What it covers

- **Every OS family grype ships a provider for** — Alpine, Debian, Ubuntu, RHEL, Rocky,
  AlmaLinux, Amazon Linux 2/2023, Oracle Linux, Fedora, SLES/openSUSE Leap, Wolfi,
  Chainguard, MinimOS, Echo, Azure Linux/CBL-Mariner, Alpaquita, Photon, Arch, Red Hat
  Hummingbird, and CleanStart — plus Bitnami application layers, across three rpmdb backends
  (BerkeleyDB, SQLite, ndb).
- **8 language ecosystems** — Go, npm, PyPI, crates.io, Maven, RubyGems, NuGet, Packagist,
  from binaries, directories, and ten lockfile formats — pnpm and yarn berry included. Not
  from inside a container image: an image scan inventories the OS packages and Bitnami layers
  above, not the language packages installed in it (D70,
  [deferred](docs/deferred-decisions.md)).
- **Every source's rating is kept** — two databases routinely disagree about one CVE; a
  finding carries each source's band, score, and fixed version, and the gate takes the
  highest, so the report agrees with its own verdict.
- **Seven gates** — `--fail-on <band>`, `--fail-on-unknown`, `--fail-on-incomplete`,
  `--fail-on-unfixable` (with `=wont-fix`), `--fail-on-kev`, `--fail-on-epss`,
  `--fail-on-eol`. Packages that cannot be evaluated are reported as skipped with a count,
  never folded silently into a clean verdict.
- **Enrichment carried by the artifact** — NVD ratings, EPSS scores, CISA KEV membership,
  and end-of-life status. KISA's Korean prose is available locally via `assay db build`.
- **Waivers that stay visible** — an `.assay.yaml` ignore file suppresses a finding you
  have accepted (mandatory reason, optional expiry), and `--vex` applies a producer's
  OpenVEX document the same way — including to an image's OS packages, and a statement that
  names an image applies only to that image. Suppressed findings never trip the gate but are counted
  and shown in every output format, each labelled with where its waiver came from, and
  GitHub code scanning sees them as dismissed, not gone. Usage in
  [docs/integrations.md](docs/integrations.md#waiving-findings-you-have-accepted).

## How it fits together

```
  image / binary / dir / SBOM  ──▶  package inventory  ──▶  vulnerability match  ──▶  verdict
```

The database is orthogonal to the scan: `assay db update` writes it, a scan only reads it,
and a scan of an SBOM or a local tarball makes no network call at all. Exit codes are a
contract — `0` clean, `1` findings at or above `--fail-on`, `2` could not run or the result
cannot be trusted — with `2` outranking `1` outranking `0`.

## Documentation

- **[docs/DESIGN.md](docs/DESIGN.md)** — the full design, the roadmap with every shipped
  feature, the architecture, and the database bootstrap guide. The roadmap checkboxes there
  are the authoritative record of what is built.
- **[docs/deferred-decisions.md](docs/deferred-decisions.md)** — what is deliberately *not*
  built, and why, each with a revisit trigger.
- **[docs/integrations.md](docs/integrations.md)** — CI integration: copy-pasteable GitHub
  Actions and GitLab CI examples, SARIF upload, and exit-code gating.
- **[docs/comparison.md](docs/comparison.md)** — how assay compares to grype (measured,
  weekly) and trivy (spec-level), and where each tool's policy deliberately differs.
- **[docs/superpowers/specs/2026-07-29-assay-roadmap.md](docs/superpowers/specs/2026-07-29-assay-roadmap.md)**
  — the reference design, every decision recorded as `D1`…`D107` with its reasoning.

Every document ships bilingually (`X.md` / `X.ko.md`); English is canonical.

## Contributing

`make build` (CGO_ENABLED=0), `make test` (`-race`, needs a C toolchain — fall back to
`go test ./...` without one), `make lint`, `make fmt`. CI runs gofmt-check → vet →
test-race → build on Go 1.26. See [docs/DESIGN.md](docs/DESIGN.md) for the architecture
constraints a change must stay inside.

## Disclaimer

`assay` reports known vulnerabilities from the data it is given; it is not a guarantee of
security, and a clean scan is not proof of safety. Verify anything that matters against the
upstream advisory.

## License

[Apache License 2.0](LICENSE).
