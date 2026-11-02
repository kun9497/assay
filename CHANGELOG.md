# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Unless an entry says otherwise, the JSON report
`schemaVersion` is unchanged. The database store schema has been 9 since v0.1.0.

## [Unreleased]

### Added
- `--config none` runs a scan with no ignore file at all: `.assay.yaml` is not looked for in
  the working directory and nothing is waived, and the report's provenance records
  `ignoreFile.path: "none"`. Discovery reads the directory the scan runs from, so a scan of a
  checkout you did not author ran under whatever waiver list it carried, and the only opt-out
  was a file saying `ignore: []`. An empty `--config` value (`--config=`), which used to mean
  "discover", is refused at parse with a message naming `none`. (QA 2026-11-02 P3 #23)

### Fixed
- The `--fail-on-incomplete` / `--fail-on-incomplete=target` verdict prints an `error:` line on
  stderr beside its exit 2, naming the counts and the flag form that fired --
  `error: N package(s) not evaluated and M check(s) incomplete (--fail-on-incomplete)` or
  `error: N package(s) or manifest(s) of the target itself not evaluated
  (--fail-on-incomplete=target)`. It was the one exit 2 with no such line, and the provenance
  sidecar's `run.error` for it, written from a private reason, said `--fail-on-incomplete` even
  when `=target` had fired; the sidecar now records the printed line like every other exit 2.
  stdout and the exit code are unchanged. (QA 2026-11-02 P3 #7)
- The table's headline for a scan in which every finding was waived AND something was not
  evaluated read "No vulnerabilities found in N package(s), but ... NOT a clean result", with the
  Suppressed block under it listing the findings. The incomplete sentences now open with "No
  unwaived vulnerabilities found in N package(s) (M suppressed), but ..."; a scan with no
  waivers prints the sentences it did before. The 0.14.0 all-waived headline is unchanged for
  a scan whose every check ran. (QA 2026-11-02 P3 #11)
- `db update`'s hint on an unsigned artifact leads with the one benign cause: the nightly pushes
  the tag in one step and signs it in the next, so a pull in that window (seconds, up to about a
  minute with retries) sees "not signed" and was steered to `--allow-unsigned`. The hint now
  says to retry in a minute if the publisher pushed moments ago, then the mirror clause, then
  the opt-out. `db update` still makes one attempt. (QA 2026-11-02 P3 #21)
- `db build` retries a Photon OS feed file through a transient failure instead of failing the
  whole build on the first non-200. The provider made one GET per major; the 2026-10-17 nightly
  publish died on a 404 from the Photon CDN for one of the three fixed
  `cve_data_photon<N>.json` URLs, and the file was back the next night. Each major is now
  fetched up to three times with the 0.5s/1s backoff Fedora's provider uses, on 429, 5xx, a
  connection reset or truncated body mid-download, and -- unlike Fedora, because these three
  URLs are fixed and known-good -- 404. Other 4xx, cancellation and a decode error on an intact
  body still fail at once; a file that is really gone fails after three attempts with the
  attempt count in the error. Every retry is announced on the build's progress output with the
  URL, the failure and the attempt. The Last-Modified reading is unchanged.
- A scan run with `--fail-on-eol` warns on stderr when the database's end-of-life data was
  generated more than seven days ago, naming the date and what to run. A ratings-only build
  with `EOL_ENABLE=0` keeps its seed's catalog, as old as the seed, and the D139 warning reads
  the build time, so such a database read as current while a release whose support had ended
  since was still judged supported. Exit code and stdout are unchanged; without the flag, and
  for undated data, nothing is said.
- The nightly publish and the backfill refuse to sign anything but a digest reference: the
  Publish step checks that `db push`'s last line is `<repo>@sha256:<64 hex>`, and the sign and
  self-check steps exit before calling cosign when the step output reaching them is empty.
  Before, an empty output -- a renamed step id, a mistyped output name -- made cosign fail three
  times and the job then reported the artifact "pushed and UNSIGNED" about a name nothing was
  pushed under. `internal/ciguard` now holds every step that maps a step output into `env` to
  such a first-line check, and to a producer declared earlier in the same job.

## [0.14.0] - 2026-11-02

### Fixed
- Inside one image layer, the last entry for a path is what the scan reads -- a later file,
  link, type change or whiteout replaces an earlier one -- as tar extraction leaves it on
  disk. Before, the first entry won, so a crafted layer could show the scan a different
  package database than the one the container runs. A hardlink still holds its target as it
  stood when the link was written (D130). (audit 2026-10-22 P4, re-verified 2026-11-02)
- A symbolic link chain inside an image is followed through 40 links, Linux's own limit;
  before, through seven. A path still behind a link after that, or a link cycle, is
  reported as not read -- in JSON `unread[]`, SARIF `assay/not-read`, the table's count, and
  as the target's incompleteness, so `--fail-on-incomplete` and `=target` exit 2 -- where
  before it looked like an absent file and the image like one with no distro or no
  packages. **The JSON report's `schemaVersion` is 16** (additive, no new field): `unread[]`
  may now name a path inside an image, and the table's count reads "path(s) not read".
  (audit 2026-10-22 P4, re-verified 2026-11-02)

- `db build --ratings-only --seed` keeps the seed's end-of-life catalog, and the provenance of
  its enrichment records, when no EOL source is configured (`EOL_ENABLE=0`). Before, the new
  metadata was written over them: the EOL rows were lost, so `--fail-on-eol` warned instead
  of gating on such a database, and `db status` showed the enrichment with no data-as-of.
  A configured EOL source still replaces the catalog. The `EOL_ENABLE=0` line says the
  seed's catalog is kept, as old as the seed. (audit 2026-10-22 P4, re-verified 2026-11-02)

- NVD's HTTP 403, which is how it answers a client over its rate limit, is retried on the same
  bounded schedule as 429 and 5xx. Before, it was held permanent, and one throttled page ended
  a sync that may have run for hours. A 403 that never clears (a rejected key, a blocked
  address) still fails, after the schedule rather than at once. (audit 2026-10-22 P4,
  re-verified 2026-11-02)
- The weekly scanner differential's verdict step fails closed: `exit ${{ steps.diff.outputs.exit_code || 2 }}`,
  as the nightly publish gate already did. An empty step output made it a bare `exit`, which
  returns 0, so a renamed step id or a mistyped output name would have turned every weekly
  run green and closed the pinned failure issue (D138). A ciguard test now holds every
  workflow's `exit ${{ steps.<id>.outputs.<name> }}` to a nonzero fallback the shell does not
  reduce to 0, with the producing step declared earlier in the same job and writing that
  output. (audit 2026-10-22 P4, re-verified 2026-11-02)

- A git, URL or path dependency in `package-lock.json` (v1 and v3), yarn v1's `yarn.lock`,
  `Cargo.lock`, `poetry.lock` or `uv.lock` is no longer cataloged under the version its own
  checkout declares. That version need not be any registry release an advisory names, so the
  scan risked both a false positive and a silent false negative. Such an entry is now counted
  as not evaluated and named on stderr (`not pinned: <lockfile>: <name> (<reason>)`), as
  `pnpm-lock.yaml`, yarn berry, `Gemfile.lock` and `Pipfile.lock` already did. A source the
  checkout itself holds -- a uv `editable` project or workspace member, a yarn v1 `file:` or
  `link:` entry -- is named and not counted, as pnpm's and berry's local entries are. An
  alternate or private registry stays cataloged, and so does a Cargo crate with no `source`
  (the workspace's own). `composer.lock` is unchanged: it records `source.type = "git"` for
  ordinary Packagist packages too. (audit 2026-10-22 P4, re-verified 2026-11-02)
- When several ranges of one advisory hold the installed version, the finding names the fix
  that clears all of them: the highest fixed bound among them, preferring a bounded range over
  an open one. Ranges are a union, so a package stays affected until it clears every range
  that holds it. Before, the first range in the file won, so the advised fix moved with the
  producer's order. The Red Hat and SUSE CSAF providers write one range per fixed build in
  lexical order, and an open range listed first hid the fix altogether. The verdict does not
  change, only the fix shown and `ratings[].fixed`. A range whose bound cannot be read no
  longer hides a later range that holds the version: that is now a finding, not a skip.
  (audit 2026-10-22 P4, re-verified 2026-11-02)
- An advisory bound that does not order against the installed version is the advisory's
  fault, not the package's. This covers Composer's `dev-master`, and a fixed or last-affected
  `"0"` that SemVer and Bitnami cannot read. Before, the skip said "this package's own
  version could not be read" and counted as target incompleteness, so
  `--fail-on-incomplete=target` failed over upstream data. (audit P4, re-verified
  2026-11-02)
- `--explain` on a finding that an ignore rule or a VEX statement suppressed explains it.
  The first line says it is not counted toward the verdict, and by which waiver and why.
  Before, it answered `no finding matches` with exit 2, as if the identifier were mistyped.
  When every finding is waived, the table's headline says so ("No unwaived vulnerabilities
  found ... N finding(s) suppressed, listed below"), instead of the sentence a clean scan
  prints. (audit P4)
- A pinned `requirements.txt` package carries a purl (`pkg:pypi/<name>@<version>`), a type
  and its file's location, as every other Python reader's packages do. Before, a VEX
  statement naming the purl never reached it, with no "matched nothing" warning, and the
  JSON report could not say which file a finding came from. (audit P4, re-verified
  2026-11-02)
- SUSE: a `known_affected` (or not-affected, or no-fix remediation) id for a package with no
  build listed in the document is stored under its product id. Before, it was skipped, and
  when it was the document's only statement the whole document was lost. On 688 live
  documents sampled 2026-11-02, 3,478 ids were dropped this way, and 142 documents yielded no
  record at all. 2,876 "affected, no fix" entries are added on SLES 12 SP5 to 16.x and their
  Leap codestreams (MozillaFirefox, kernel, terraform, apache2 among them). No fixed version
  changes. The `db build` progress line also prints the SUSE leaves with no readable purl,
  which were counted and never shown. A database change: it reaches `db update` with the
  nightly after merge. (D159, revises D126, audit B2)

## [0.13.0] - 2026-11-02

### Changed
- `db build` fails when Canonical's Ubuntu CVE tracker parses to no tuple, or stamps no fix
  state on any fix-less Ubuntu range, and says to set `UBUNTU_TRACKER_ENABLE=0` to build
  without Ubuntu fix states on purpose. `db push` refuses a candidate in which any Ubuntu
  release holds under 80% of its published fix states, counted from the database
  (`--force` overrides). Before, a tracker that stopped parsing published an artifact with
  every Ubuntu wont-fix and not-fixed state gone (2,094,636 on 2026-10-29) and nothing
  failed. (D157, revises D85, audit A15)
- A rating that carries only a CVSS v2 vector -- NVD's for every CVE it never re-scored,
  72,405 of its ratings in the 2026-10-27 database -- is banded from the v2 base score on
  NVD's v2 table (Low/Medium/High, no Critical), where it was `unknown`. v2 is used only
  when nothing else in the same record scores. Findings that were unknown can now carry a
  band and trip `--fail-on`. The JSON report's `schemaVersion` is 15 (additive): a rating
  banded this way carries `"cvssV2": true`, and `--explain` marks it `(CVSS v2)`. A
  finding's ratings now rank by band before score, so a v2 High never outranks another
  source's Critical, and SARIF's `security-severity` stays inside the finding's band.
  (D156, audit A14)

### Security
- The jobs that hold the signing key run nothing pinned by a tag alone. The nightly
  publish installs grype from its release tarball checked against a committed sha256
  (it ran `curl get.anchore.io/grype | sh`), and the trivy and goreleaser actions are
  pinned by commit. (audit A18)
- Builds are held to go.mod's `toolchain` line, now `go1.26.10`. v0.12.0 was built with
  go1.26.9, which carries GO-2026-6809 (crypto/x509, fixed in go1.26.10).
  `scripts/check-go-toolchain.sh` fails a release or CI build below the floor. Each
  GoReleaser build scans its own binary with govulncheck (`scripts/release-vulncheck.sh`)
  before anything is published. (QA 2026-10-30)

### Fixed
- SARIF output reports components the cataloger could not use -- no version, no purl, an
  unsupported ecosystem -- as `assay/not-evaluated` results with their counts. Before, GitHub
  code scanning showed a clean scan where the table said they were not evaluated.
  (D158, audit A16)
- An image layer that replaces a package database, `os-release` or a dpkg/pacman/Bitnami
  record with a directory, device or FIFO now hides the lower layer's file, as the running
  container sees it. Before, the deleted file was still read, and the scan reported an
  inventory the image does not have. A file turned into a directory writes no `.wh.`
  marker, so the whiteout rules never caught it. (audit A10)
- A line over 64 KiB in a Gemfile.lock, Cargo.lock, uv.lock, requirements.txt or a jar's
  pom.properties no longer hides every package after it. The readers stopped at the line
  without an error, and the scan reported the rest as the whole file: exit 0, nothing
  incomplete. (QA 2026-10-30)
- A single-version or empty window is judged on its own when the range lists both opens
  before both closes (`[introduced 1, introduced 3, last_affected 1, last_affected 3]`), which
  had been read as `[1, 3]`. (QA 2026-10-30, revises D154)
- `db update` and `db build --seed` retry an HTTP/2 stream reset mid-download, as they
  already retried a cut HTTP/1 body. A pull that was cancelled or ran past `--timeout` is no
  longer retried. (QA 2026-10-30, revises D140)
- A VEX statement naming the outer index of a nested image index applies to the image
  selected through it, on registry and `oci-dir:` targets alike. (QA 2026-10-30, revises D121)
- An Alpine edge image (`VERSION_ID=3.25.0_alpha20260805`) is reported as not evaluated
  instead of being judged against stable Alpine 3.25's advisories. OSV publishes no edge
  ecosystem. (audit A11)
- A Go binary built with a non-default `GOEXPERIMENT` (`go1.26.7-X:fieldtrack`) catalogs
  stdlib at its release version. Before, the experiment list read as a prerelease no
  comparison accepts, and every stdlib advisory was skipped. (audit A12)
- When a record links two findings for one package, the merged finding's disclosure of an
  apk provides join and of a mirrored advisory's origin follows the displayed record.
  (audit A13, D10)
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

[Unreleased]: https://github.com/kun9497/assay/compare/v0.14.0...main
[0.14.0]: https://github.com/kun9497/assay/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/kun9497/assay/compare/v0.12.0...v0.13.0
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
