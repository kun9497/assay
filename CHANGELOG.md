# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Unless an entry says otherwise, the JSON report
`schemaVersion` is unchanged. The database store schema has been 9 since v0.1.0.

## [Unreleased]

### Fixed
- An image layer that replaces a package database, `os-release` or a dpkg/pacman/Bitnami
  record with a directory, device or FIFO now hides the lower layer's file, as the running
  container sees it. Before, the deleted file was still read, and the scan reported an
  inventory the image does not have. A file turned into a directory writes no `.wh.`
  marker, so the whiteout rules never caught it. (audit A10)
- `--fail-on-eol` no longer goes red a day early. A release counted as end of life from the
  first instant of the day EOLFrom names (09:00 KST on that day), while D87 promises that day
  is not yet EOL; it is now EOL from the day after. Extended support likewise now covers the
  whole EOESFrom day. Days are UTC. `db build`'s carry-forward of frozen keys (D110) made the
  same comparison and now also treats a release as past EOL only from the day after EOLFrom.
  (audit A9, D87)
- A native gem's platform (`nokogiri (1.13.8-x86_64-linux)` in a Gemfile.lock, or the same
  text in a syft SBOM's gem version) is no longer read as part of its version. Before, every
  comparison against an x86_64 build was an incomplete check, and other builds sorted as
  prereleases: an advisory introduced at the installed version was missed and one fixed at
  it was a false positive.
  On rails/rails's own Gemfile.lock, 130 incomplete checks became 0, 26 findings are no
  longer missed and 2 false positives are gone. The purl keeps the platform. (D155, audit A6)
- A version range whose later window is listed before an earlier one that closes where the
  later one opens (`introduced 2.0, fixed 3.0, introduced 1.0, fixed 2.0`) judged every
  version in the later window clean. A close now sorts before an open at the same version,
  and a window that opens and closes at one version is judged on its own bounds. No record
  in the published database had the shape; judged at each of their own bounds, its 536
  ranges holding a tie keep every verdict (2,892 judgments). (D154, audit A7)
- Image scans of rpm distros compare a source-keyed advisory against the source rpm's
  version, not the binary's. Before, a subpackage with its own version or epoch was judged
  in the wrong namespace: perl's subpackages and npm never cleared their source's fix
  (−342 false positives on ubi9/perl-532, −46 on ubi8/nodejs-18), and mod_ssl's epoch could
  hide an httpd fix on source-keyed feeds. On Azure Linux and Photon, whose feeds carry no
  usable epoch, the source version carries none. (D153, audit A4)
- SLES service packs past general support (12 SP5, 15 SP4–SP6 and others with an LTSS
  track): when SUSE lists the mainline product as affected with no fix and the SP-LTSS
  product as fixed, the LTSS fix is kept. Before, the fix was dropped, and an LTSS image with
  the fix installed scanned "affected, no fix available" (14,731 entries on the 2026-10-27
  archive). openSUSE Leap results are unchanged. A database change: it reaches `db update`
  with the nightly after merge. (D149, revises D91)
- In SPDX SBOMs, a binary rpm linked to its source by a `GENERATES` / `GENERATED_FROM`
  relationship is judged on the source's version under the source's name. Before, npm was
  compared with nodejs fixes (a false positive on Red Hat's CVE-2023-23920 for the fixed
  npm) and Fedora's mod_ssl epoch could hide an httpd fix. (D152, revises D143)
- `install.sh` verifies signatures on macOS: it no longer passes base64 a file argument,
  which Apple's base64 rejects, so every genuine release was refused there. (D151)
- A signature payload that cannot be downloaded (403, 404, 503) is reported as a fetch
  failure, not as a signature that does not verify: `db update` says so and still refuses,
  and the published `status.json` keeps its last observation instead of showing
  `signed: false`. (D150)

## [0.12.0] - 2026-10-27

### Added
- An image scan now tells you, on stderr and in SARIF (rule `assay/inventory-scope`, note
  level), that application packages inside the image (npm, Python, Java, Go binaries) were
  not checked, and suggests what to scan instead. The exit code, the table and the JSON are
  unchanged. (D141)
- A scan warns on stderr when its database was built more than seven days ago. The exit code
  and stdout are unchanged. (D139)
- The nightly publishes `status.json` (digest, `builtAt`, `dataAsOf`, signature state,
  last success) to the `status` branch. A failing ops workflow keeps one pinned GitHub issue
  open until it recovers. (D138)
- `assay db status --output json` writes the same facts as the table as one JSON
  document with its own `schemaVersion` (1). (D147)
- `install.ps1`: a Windows installer for PowerShell 5.1 and 7 that verifies the release's
  checksums signature against the embedded keys before installing `assay.exe`. (D148)
- `SECURITY.md` (private reporting through GitHub), `CONTRIBUTING.md`, this changelog, and
  [`docs/compatibility.md`](docs/compatibility.md), which states what a `schemaVersion` bump
  means for each machine-readable output. From report schema 15 on, every change to the
  JSON report bumps `schemaVersion`.

### Changed
- `db status`, `db ref` and `db build --seed <ref>` refuse an argument they do not take
  (exit 2) instead of ignoring it. (D147)
- `assay help` and the design document name every target kind and lockfile a scan reads,
  and DESIGN.md's scope section lists what a scan does not cover.
- CI regression gate: `az2023` and `wolfi` now have real floors, and the gate also checks
  the `incompleteChecks` and `targetIncomplete` counts against per-target limits. A new
  per-target ceiling (`maxAssayOnlyFixed`) caps assay-only findings that carry a fix.
  These change only the project's own CI and nightly gate, not the binary. (D145, D146)

### Fixed
- Ubuntu FIPS hosts using the older `.fips.N` and `<digit>fipsN` version spellings are now
  reported as not evaluated. Before, they were judged against mainline data and could scan
  clean while vulnerable. (D142)
- In SPDX SBOMs such as Red Hat's, a binary rpm now takes its source package from
  `GENERATES` / `GENERATED_FROM` relationships, so Red Hat advisories reach packages such as
  `openssl-libs`. Before, they reported clean. (D143)
- On Oracle Linux, a non-kernel package that two ELSAs fix for the same CVE is now held to
  the lowest fix of its own release train instead of being dropped. openssh CVE-2024-6387,
  glibc CVE-2023-4911 and 389-ds-base CVE-2025-2487 are now matched; no release had matched
  them since Oracle Linux support landed (D74). A database change: it reached `db update`
  with the 2026-10-26 nightly, for v0.11.0 binaries too. (D144)
- `db update` and `db build --seed` retry a database layer download that is cut off
  mid-stream, up to three attempts. (D140)
- When building a database, the `git fetch` of the Ubuntu CVE tracker now retries a response
  that was cut short. (no D-number; PR #185)

## [0.11.0] - 2026-10-23

### Changed
- What `db update` pulled is now recorded inside the database itself. The
  `<dbPath>.artifact.json` sidecar is no longer written, and an old one is removed. (D127)

### Fixed
- Hardlinks in images resolve to the file from the layer that created them. (D130)
- An unreachable registry is reported as an error instead of a panic. (no D-number; PR #168)
- A VEX image reference that cannot be parsed now applies to no target, with a warning,
  instead of applying to every target. (D124)
- Matching: npm aliases are matched under their real registry name, and the install path is
  kept in JSON as `locations[].install` (D132). Ubuntu and RPM lineage skips only apply
  within their own ecosystem (D133). A binary package with the same name as its source is
  judged on the source version (D134). `--fail-on-epss=NaN` is rejected when flags are
  parsed; before, it silently disabled the gate.
- SUSE data: the update pass reads SUSE's new year-prefixed layout. Several SUSE package
  names and fix versions that had been missed are now matched, including 16,736 kernel-coco
  builds. The SLE-to-Leap mirror now respects Leap's own statements. A corrected document no
  longer leaves an outdated record behind. (D122, D125, D126, D128, D129, D131, D135)
- openSUSE Leap 16.1 now receives SLES 16.1 data through the D108 mirror. (PR #171)
- Red Hat downloads the full archive before applying updates (D135). NVD ratings that NVD
  withdraws are removed from the database (D136).

### Security
- The published database is signed with cosign. `db update` and `db build --seed` check the
  signature against keys built into the binary before writing anything. An unsigned database
  is refused unless you pass `--allow-unsigned` (`db update` only; `--seed` has no opt-out).
  A signature that does not verify is always refused. Mirrors must copy the
  `sha256-<digest>.sig` tag. (D137)
- Release checksums are signed, and `install.sh` checks the signature with `openssl` or
  `cosign`. The new installer refuses releases before v0.10.0. (D137)
- Every image layer is read in full and checked against its digest before its files are
  used. `oci-dir:` and `docker-archive:` images had not been checked before. A mismatch
  exits 2. (D123)

## [0.10.0] - 2026-10-13

### Added
- Every JSON and SARIF report carries a `provenance` object: the tool build, the database,
  the target, every gate setting and every waiver. It holds no timestamp, so the same inputs
  still give byte-identical reports. `--provenance <path>` also writes a sidecar file with
  the run time and exit code on every exit after argument parsing.
  `db update` now writes `<dbPath>.artifact.json`, which records what it pulled.
  **(report schemaVersion 14)** (D120)
- OS packages found in an image (for distros with a measured namespace, which excludes
  CleanStart) now have syft-style purls, so `--vex` reaches them. A VEX statement that names
  an image applies only to that image. Source statements marked `arch=src` or `arch=source`
  cover every binary built from that source. **(report schemaVersion 14)** (D121)

### Changed
- For `--vex` users: findings that a VEX document clears are now suppressed on image OS
  packages. A statement that names an image no longer suppresses findings on any other
  target. (D121)

## [0.9.0] - 2026-10-13

### Added
- Scanning a registry image now uses credentials, tried in this order:
  `ASSAY_REGISTRY_AUTH_*` environment variables, then your docker login, then your podman
  login. No credential value is ever printed. A half-set credential, or a broken docker or
  podman config file, exits 2. (D118)
- `--platform os/arch[/variant]` picks the image platform the way containerd does, for
  registry, `oci-dir:` and `docker-archive:` images. The report records the platform and
  digest that were scanned in a new top-level `image` object.
  **(report schemaVersion 13)** (D119)

### Fixed
- On 32-bit arm hosts, the default platform is now `arm/v7` instead of the first arm entry
  in the index. `arm64/v8` now matches an index whose arm64 entry has no variant. An index
  nested inside another index now works when pulled from a registry. (D119)

## [0.8.0] - 2026-10-12

### Added
- A provider can declare that an upstream ecosystem key was renamed. The old key is then
  retired instead of being kept as frozen. The first case was `Echo:PyPi` → `Echo:PyPI`.
  `db status` shows a `renamed:` line. (D115)

### Fixed
- `db build` and `db update` take an operating-system lock on `<dbPath>.lock`. A second
  writer exits 2 immediately instead of silently racing the first. (D116)

### Security
- A jar larger than the 512 MiB per-file limit is refused before its index is read. Before,
  a crafted archive could use unbounded memory. (D112, revised)

## [0.7.0] - 2026-10-07

### Added
- Read caps: 512 MiB for each file read from an image layer and for each SBOM, and 2 GiB in
  total for an image scan. Reaching a cap exits 2 and names the file. `--timeout <duration>`
  stops an image scan with exit 2. (D112)
- `--db-max-rating-age` gates the age of NVD, EPSS and KEV data separately. (D113)

### Changed
- `--db-max-age` now judges only the providers whose data the scan actually uses. A frozen
  key counts as old as its freeze date. (D113, revising D59)
- The nightly database is held to the same regression floors as the weekly comparison
  before it is published. (D114)

## [0.6.0] - 2026-10-01

### Added
- The JSON report gains `coverage[]`, one entry per ecosystem key the scan touched, with its
  state (`live`, `frozen`, `not-in-database`, `no-comparer`). It also gains `distro` and,
  for image scans, `inventoryScope`. The table lists every key that is not live. SARIF
  carries `coverage` and an `assay/frozen-data` result for each frozen key.
  **(report schemaVersion 12)** (D111)
- A release key that the upstream stops serving is kept and marked frozen instead of
  disappearing. Every output format shows findings under a frozen key with the freeze date.
  (D110)

### Changed
- A manifest that can't be read counts toward `summary.targetIncomplete`, so
  `--fail-on-incomplete=target` exits 2 on it. The JSON gains `unread[]`.
  **(added in report schemaVersion 11, which was never released; first shipped here in 12)**
  (D109)

## [0.5.1] - 2026-09-28

### Fixed
- `db push` refuses to publish a database that has lost coverage compared with the one
  already published (`--force` overrides). The same release also includes database-build
  fixes: NVD resumes from the seed's window, `--ratings-only` replaces EPSS/KEV, and the
  Ubuntu tracker `git fetch` retries. (no D-number; PR #135)
- A directory scan now reports a subtree it could not open as an unread manifest, and exits
  2 under `--fail-on-incomplete`. Before, it reported clean. (no D-number; PR #136)

## [0.5.0] - 2026-09-15

### Added
- openSUSE Leap images inherit advisories from the SLE codestream they are built from, so
  findings remain after SUSE drops a Leap release from its feed. A cross-mapped fix is marked
  in every output format (`crossMappedFrom` in JSON, an optional field; the schema version
  stays 10). (D108)

## [0.4.1] - 2026-09-07

### Changed
- Performance: severity scoring is cached within a scan, SARIF rule help is built once,
  PEP 440 parsing is faster, and database builds spool the OSV archive to disk. The output
  is byte-identical. (no D-number)

### Fixed
- The CISA KEV fetch sends a named `User-Agent`. (no D-number)

## [0.4.0] - 2026-08-30

### Added
- Severity colors in the table on an interactive terminal. `NO_COLOR` is honored, and piped
  output is byte-identical. (D107)

### Fixed
- Azure Linux / CBL-Mariner data now comes from Microsoft's OVAL feed directly. The OSV.dev
  copy had been frozen since March, and all 140 missing findings were recovered. This
  matters for self-built databases; the published one was already repaired. (D106)

### Security
- Built with go1.26.7, which fixes six reachable standard-library vulnerabilities, and with
  `klauspost/compress` v1.18.7.

## [0.3.0] - 2026-08-28

### Added
- `pnpm-lock.yaml` and yarn berry `yarn.lock` are read. (D103)
- `--vex <path>` (repeatable) applies OpenVEX documents. Only `not_affected` and `fixed`
  suppress findings, and every suppression is labeled with its source.
  **(report schemaVersion 10: suppressed records gain `source`)** (D104)

## [0.2.0] - 2026-08-27

### Added
- Ignore rules in `.assay.yaml` (or a file given with `--config`). A reason is required and
  an expiry is optional. Waived findings are counted and shown in every output format, never
  hidden. **(report schemaVersion 9: `suppressed[]`, `summary.suppressed`)** (D102)

## [0.1.0] - 2026-08-27

### Added
- First tagged release. Builds a package inventory from images, Go binaries, directories
  and CycloneDX/SPDX SBOMs, and matches it against a database assay builds or pulls itself
  (`db build`, `db update`). KISA/KNVD Korean advisory data is a first-class source. Covers
  every OS family grype ships a provider for, plus Bitnami layers and eight language
  ecosystems. Gives CI an exit code of 0, 1 or 2. Output as table, JSON or SARIF.
  **(report schemaVersion 8; store schema 9)** (decision log D1–D101)

[Unreleased]: https://github.com/kun9497/assay/compare/v0.12.0...main
[0.12.0]: https://github.com/kun9497/assay/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/kun9497/assay/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/kun9497/assay/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/kun9497/assay/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/kun9497/assay/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/kun9497/assay/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kun9497/assay/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/kun9497/assay/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/kun9497/assay/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/kun9497/assay/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/kun9497/assay/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kun9497/assay/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kun9497/assay/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kun9497/assay/releases/tag/v0.1.0
