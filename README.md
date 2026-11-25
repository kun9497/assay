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
# Prebuilt binary (Linux/macOS, amd64/arm64) — onto your PATH; Windows below
sh -c 't=$(mktemp) && (curl -sSfL --connect-timeout 5 --proto-redir =https -o "$t" https://raw.githubusercontent.com/kun9497/assay/d9a7b309d8c4aba10ac6bc2ce30eea994273750a/install.sh || curl -sSfL --connect-timeout 5 --proto-redir =https -H "Accept:application/vnd.github.raw+json" -o "$t" "https://api.github.com/repos/kun9497/assay/contents/install.sh?ref=d9a7b309d8c4aba10ac6bc2ce30eea994273750a") && sudo sh "$t" -b /usr/local/bin; s=$?; rm -f "$t"; exit $s'
```

The script embeds the project's signing key and verifies the release's checksums
signature with `openssl` (or `cosign`) before the checksum, then picks the right asset for
your OS/arch. The URL pins the installer to a Git commit. If the raw host is unavailable, the command retrieves the same file and commit through GitHub’s contents API. The script is downloaded to a
temporary file (`mktemp`) and run only if the download succeeded; the file is removed afterwards
whether the install succeeded or failed (an interrupted run can leave it in `$TMPDIR`, readable
only by you), and the line's exit status is the install's (piping `curl`
into `sh` had returned 0 on a failed download, and a fixed file name in the working directory
had overwritten a file of that name). Nothing in the current directory is touched. Without `-b`
it installs to `./bin` (no sudo needed — add it to your PATH yourself); to install another
release, put its tag after `-b /usr/local/bin` inside the same line (`… -b /usr/local/bin
vX.Y.Z; s=$?; …`), verified against the same keys. A release whose checksums file carries no
signature is refused, never installed on the checksum alone: v0.10.0 is the first signed
release, so anything older goes through `go install` or the release page.

If you installed as root with an installer older than v0.18.3, check the executable's owner
and rerun the command above if it is not root. Older installers could restore the build
runner's UID from the archive; this was confirmed in the v0.18.0 release assets. The current
installer creates the executable as the installing user.

On a runner without sudo, replace `sudo sh "$t" -b /usr/local/bin` in the install line with
`sh "$t" -b "$HOME/.local/bin"`. Run `export PATH="$HOME/.local/bin:$PATH"` in the scan step.

On Windows, run the following command in PowerShell 5.1 or 7. v0.18.5 shipped no Windows binary; v0.18.6 ships one again.

```powershell
& { $ErrorActionPreference = "Stop"; try { $s = irm -TimeoutSec 8 https://raw.githubusercontent.com/kun9497/assay/d9a7b309d8c4aba10ac6bc2ce30eea994273750a/install.ps1 } catch { $s = irm -TimeoutSec 8 -Headers @{Accept="application/vnd.github.raw+json"} "https://api.github.com/repos/kun9497/assay/contents/install.ps1?ref=d9a7b309d8c4aba10ac6bc2ce30eea994273750a" }; & ([scriptblock]::Create($s)) }
```

`install.ps1` verifies the signature with .NET and installs `assay.exe` to
`%LOCALAPPDATA%\Programs\assay` (`$env:ASSAY_INSTALL_DIR` overrides the directory and
`$env:ASSAY_VERSION` selects a release). Add the install directory to this PowerShell session
before running the quick start. If you set `ASSAY_INSTALL_DIR`, use that directory instead.

```powershell
$env:Path = (Join-Path $env:LOCALAPPDATA 'Programs\assay') + ';' + $env:Path
```

**If GitHub downloads time out**, use Git, Python 3 and curl from a directory that does not yet contain `assay-install`. Run each command after the previous one succeeds. The Git checkout supplies the pinned installer even if the raw host and public API are unavailable.

```text
git clone --no-checkout https://github.com/kun9497/assay.git assay-install
git -C assay-install checkout --detach d9a7b309d8c4aba10ac6bc2ce30eea994273750a
```

On Linux or macOS run `python3 assay-install/scripts/recover-install.py -b "$HOME/.local/bin"`. On Windows run `py -3 assay-install/scripts/recover-install.py` (or use `python` if that starts Python 3). Windows recovery runs the checked-out script under the current PowerShell execution policy. On a connection failure, the helper retries the official HTTPS asset host at other addresses returned by your DNS resolver. The installer verifies the signed checksums before replacing the binary. A proxy that blocks every GitHub asset address still needs access to the release assets. GitHub's unauthenticated contents API also has a [per-IP rate limit](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).

<details>
<summary>Other ways to install</summary>

```bash
# With Go
go install github.com/kun9497/assay/cmd/assay@latest

# From source
git clone https://github.com/kun9497/assay.git && cd assay && make build   # -> bin/assay
```

When building from source, use a Go version patched for CVE-2026-97054
(1.26.11 or later in the 1.26 series, or 1.27.4 or later in the 1.27 series).
Run `go version -m <path-to-assay>` to check which Go version built your executable.
[Go vulnerability report](https://pkg.go.dev/vuln/GO-2026-6859)

The [release page](https://github.com/kun9497/assay/releases) lists the prebuilt binaries and signed checksums available for each version.
</details>

## Quick start

Install Assay on your CI runner using the instructions above. Run this as one shell step.
It downloads the signed DB from GHCR and scans a public Alpine image without a Docker daemon or login.
Allow disk space for the local DB. The November 2026 Windows measurement was a **6 GiB logical
file size**; see the [measurement and memory model](docs/operating-envelope.md#3-memory-model).
Size varies by artifact and platform. Updating an existing DB temporarily needs room for the
old and new copies together.
For your build, replace `IMAGE` with the digest your build pushed and set `--platform` to its deployment platform.

```sh
set -e
assay version
assay db update
assay db status --output json > assay-db.json

IMAGE='mirror.gcr.io/library/alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1'
assay scan "$IMAGE" --platform linux/amd64 --config none \
  --fail-on high --fail-on-incomplete --output json > assay-report.json
```

`db update` verifies the signature before installing the DB. In `assay-db.json`,
`artifact.signature` should be `verified`. `artifact.digest` and `artifact.signedBy` identify
the DB and signing key. `--config none` prevents a checkout's `.assay.yaml` from waiving findings.

| Scan exit | CI verdict with these flags |
|---|---|
| `0` | **Pass.** No unsuppressed High or Critical finding and no reported incomplete check. Lower-severity findings can still appear. |
| `1` | **Fail.** At least one unsuppressed High or Critical finding. Read `findings` in the report. |
| `2` | **Fail.** The scan could not finish or an evaluation was incomplete. Check stderr and, if a report exists, its `summary` and `skipped` entries. This takes precedence over `1`. |

Keep the scan as the last command in the step. Inspect or upload the report in a separate step
that also runs on failure. A pipe to `jq` can hide the scanner's exit code. An early error can
leave an empty report file. Read `inventoryScope` for what the image scan covered.
If `summary.components` is zero, no packages were inventoried. To see findings without a severity gate, run
`assay scan "$IMAGE" --platform linux/amd64`. A pinned image's findings can change with the DB.

<details>
<summary>Run the gate in a PowerShell CI step</summary>

If the installer ran in an earlier step, add its directory to this step's PATH as shown under Install.

```powershell
$ErrorActionPreference = 'Stop'
assay db update
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
assay db status
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$image = 'mirror.gcr.io/library/alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1'
assay scan $image --platform linux/amd64 --config none --fail-on high --fail-on-incomplete
exit $LASTEXITCODE
```

</details>

Copy the [GitHub Actions workflow](docs/ci/github-actions.yml) into `.github/workflows/` to publish
SARIF alerts to the Security tab. GitHub.com supports this for public repositories. For a private
or internal organization repository, enable GitHub Code Security in the repository settings.
[GitHub's SARIF upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)

On GitLab, add the [GitLab CI job](docs/ci/gitlab-ci.yml) to your `.gitlab-ci.yml` to save
reports as job artifacts. Both examples include installation.
To gate a local Docker build before pushing, save it with
`docker save -o image.tar my-app:ci` and use `docker-archive:image.tar` as the scan target above.
Use `assay scan sbom.cdx.json` for a CycloneDX/SPDX SBOM or `assay scan ./my-service`
for a Go binary or directory with lockfiles. `--output sarif` writes a code-scanning report
and `--explain` shows the evidence for a finding.

**Private registries.** Scanning a registry image tries, in order:
`ASSAY_REGISTRY_AUTH_USERNAME` + `ASSAY_REGISTRY_AUTH_PASSWORD` (or
`ASSAY_REGISTRY_AUTH_TOKEN`), then your `docker login` (`DOCKER_CONFIG` or
`~/.docker/config.json`, credential helpers included), then podman's (`REGISTRY_AUTH_FILE` or
`$XDG_RUNTIME_DIR/containers/auth.json`). The environment credential is offered only to the
target's own registry unless `ASSAY_REGISTRY_AUTH_AUTHORITY` names another; a half-set one is
exit 2, and values are never printed. `--platform os/arch[/variant]` selects the image platform.
The default is Linux on the Assay binary's architecture (for example, `linux/amd64` on Windows x64).
The scanned platform and digest appear on stderr and in the JSON `image` object.

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
  from binaries, directories, and thirteen lockfile formats — pnpm and yarn berry included.
  Inside a container image, two fixed locations (D160): npm packages installed under the global
  `node_modules` roots and Go binaries in the standard bin directories. Python, Java and
  anything elsewhere in the image are not read (D70, [deferred](docs/deferred-decisions.md)),
  and every image scan says exactly what it read and did not on stderr, in SARIF and in the
  JSON's `inventoryScope` (D141).
- **Releases the upstream stopped publishing stay, marked** — a key the upstream no longer
  serves is frozen (D110): its last advisories are kept, every finding on it carries
  `frozenSince`, and fixes published upstream since may be missing — the table, SARIF and
  `--explain` say so beside the date, and JSON carries the date as `frozenSince`. Debian 11 is
  frozen today (bullseye's LTS ended 2026-08-31;
  Freexian ELTS fixes are not read), and so is every other key its upstream dropped.
  Operating guidance for a service in
  [docs/integrations.md](docs/integrations.md#operating-assay-on-targets-you-did-not-author).
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
contract — `0` no gate tripped, `1` findings at or above `--fail-on`, `2` could not run or the
result cannot be trusted — with `2` outranking `1` outranking `0`. `0` is not "no
vulnerabilities": a scan run without a `--fail-on*` flag lists its findings and exits 0, and so
does a scan whose findings were all waived, or an SBOM with no components. Read the report's
summary, not the exit code alone.

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
  — the reference design, every decision recorded as a numbered `D` entry with its reasoning.
- **[docs/compatibility.md](docs/compatibility.md)** — what a consumer of the JSON, SARIF and
  database outputs can rely on across releases, and what a `schemaVersion` bump means.
- **[CHANGELOG.md](CHANGELOG.md)** — what changed in each release.

Every document ships bilingually (`X.md` / `X.ko.md`); English is canonical.

## Contributing

`make build` (CGO_ENABLED=0), `make test` (`-race`, needs a C toolchain — fall back to
`go test ./...` without one), `make lint`, `make fmt`. CI runs gofmt-check → vet →
test-race → build on Go 1.26. [CONTRIBUTING.md](CONTRIBUTING.md) has what a change needs;
report a security problem privately, as [SECURITY.md](SECURITY.md) describes.

## Disclaimer

`assay` reports known vulnerabilities from the data it is given; it is not a guarantee of
security, and a clean scan is not proof of safety. Verify anything that matters against the
upstream advisory.

## License

[Apache License 2.0](LICENSE).
