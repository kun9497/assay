# Application packages inside container images — fixed-location probes (D70 revised)

*English · [한국어](2026-11-09-image-app-probe-design.ko.md)*

Status: **approved 2026-11-09, implemented as D160** (the `ownedBy` field was deferred to a
follow-up on finding that no OS cataloger reads file lists today, and landed as D162 the same
day — `locations[].ownedBy` is `{name, version}` rather than the one string proposed below;
`applicationPackages` says `partial`; the probes share one layer pass). Decision record: roadmap D160, revising D70. Reopens the deferral "Application
packages inside container images" in `docs/deferred-decisions.md` on new information: the
2026-11-04 QA's §8 item S-1 names the gap as a blocker for the service, and a 2026-11-09
measurement of all 26 scanner-diff targets shows exactly where the gap sits.

## Intent

An image scan inventories the operating system and Bitnami's markers, not the language
packages installed on top (D70). D141 discloses that on stderr and in SARIF; D111's
`inventoryScope.applicationPackages` says `not-read` in JSON. The service that wraps assay
will close the gap today with a pinned SBOM generator (the deferred entry's "service-side
hybrid", decided 2026-11-09). This document is the assay-side half: read the two shapes the
gap actually takes, say so in the report, and leave everything else disclosed as before.

## What was measured (2026-11-09)

`s1probe` streamed every layer of the 26 scanner-diff targets (linux/amd64) and counted what a
fixed-location probe would read and what it would miss (evidence: QA folder
`main-qa-2026-11-04/s1-probe-2026-11-09/`). The weekly differential of the same day
(run 42537001178) has grype-only application tuples on three targets: ubi8n18 npm 41,
bci156 go-module 47, cleanstart-postgres go-module 1 — 89 in all, and 0 of lockfile, jar or
Python type.

| what | where it was found | count |
|---|---|---|
| installed `package.json` under `usr/lib/node_modules`, `usr/local/lib/node_modules`, `opt/app-root/src/node_modules` | ubi8n18 only: 236 (npm's own tree 202, nodemon 33, corepack 1; 233 nested; 199 distinct names, 24 names at two or more paths, 22 of them at two or more versions) | 236 |
| installed `package.json` under any other `node_modules` | none, on any of the 26 | 0 |
| Go binaries (ELF with Go build info) directly in `usr/bin`, `usr/local/bin`, `bin`, `sbin`, `usr/sbin`, `usr/libexec`, `usr/local/sbin` | bci156 `usr/bin/container-suseconnect`; cleanstart-postgres `usr/bin/gosu`; archlinux `usr/bin/captree` | 3 |
| Go binaries under `opt/`, `app/`, `usr/lib*`, `usr/share/`, `usr/local/` | none | 0 |
| `*.dist-info` | ubi8n18 2, ubi9 5, ubi10 9, alma9 2, ol9 2, archlinux 1 — inferred OS-owned (grype's ownership-overlap rule drops them; 0 grype-only python tuples) | 21 |
| `*.egg-info` | ubi8n18 14, ubi9 9, ubi10 6, rocky9 1, alma9 2, ol9 2, az2023 2, amazonlinux2 3 — the same inference | 39 |
| jars | liberica21 1, bitnami-legacy-pg 3 (0 grype-only java tuples) | 4 |
| lockfiles of any of the thirteen formats | none | 0 |

Two shapes account for every measured tuple: **the global npm tree** and **Go binaries in
standard bin directories**. Three of ubi8n18's 41 npm tuples are CVEs assay already reports
under the owning RPM (`npm`, `nodejs-nodemon`): the tree is RPM-owned.

## Decision in one paragraph

An image scan gains two **fixed-location probes**, run after the OS inventory with the
primitives the image already has: (1) every installed `package.json` under the three
node_modules roots above becomes an `npm` package with its name, version and install path;
(2) every executable regular file directly in the seven bin directories above whose first
four bytes are ELF and that carries Go build info becomes the `Go` packages the `file:`
target path already derives (main module, dependencies, stdlib). Nothing else inside an
image is read — Python `dist-info`, jars, `node_modules` elsewhere, Go binaries elsewhere stay
`not-read` and the report says which. The probes run under D112's existing budget with no
new limit. The JSON report says what was read and what was not per ecosystem, and the weekly
differential stops treating npm and go-module as "the types an image scan does not read".

## Why these two shapes and not a whole-tree walk

D70's reason still holds for the whole tree: a `node_modules` or a jar at a path nobody named
needs a walk the Source interface does not expose, and reading every file under `/` for ELF
magic collides with D112's 2 GiB per-scan budget on a large image (the budget is "error, not
truncation", so the OS verdict would be lost to the application pass — an inversion). The
measurement says the whole tree is not where the gap is: 26 images, 0 application files
outside the fixed locations. A probe of named locations needs no new primitive
(`FilesMatching` already matches at any depth under a named directory and hands back bytes
with their layer — the deferred entry's recorded groundwork) and bounds its own cost by the
size of those locations. Python and Java stay out because the measurement found 0 tuples and
because the dist-info files found are OS-owned: reading them without the package manager's
file ownership would report every RPM-installed Python module twice. The day a `maxGrypeOnlyApp`
ceiling trips on a python or java type, that is the next increment, on the same primitives.

## Rules

**npm probe.**
- Roots, fixed in code like D112's limits: `usr/lib/node_modules`, `usr/local/lib/node_modules`,
  `opt/app-root/src/node_modules`. A root that does not exist costs one `FilesMatching` pass that
  finds nothing.
- An *installed* `package.json` is one whose parent directory's parent is `node_modules`, or is
  `@<scope>` whose parent is `node_modules` (syft's rule). `esm/package.json` inside a package,
  `*-package.json` and test fixtures are not packages.
- Name and version come from the file; a file with no `name` or no `version` is a counted skip
  (D36's cause: `unreadable package.json`), never a package with an empty field.
- Nested trees are packages in their own right: `node_modules/npm/node_modules/minimatch` is
  `minimatch` at that version, located at that path. Two copies of one name at two versions are
  two packages (24 such names on ubi8n18); the finding carries each one's location, so a reader
  sees which copy is affected.
- Ecosystem key `npm`; purl `pkg:npm/<name>@<version>` (scoped names URL-escaped as the npm
  lockfile cataloger already spells them), so `--vex` reaches them (D121).
- **Ownership.** When the OS inventory holds a package whose file list contains the root the tree
  sits under — the rpmdb and dpkg catalogers already read file lists for D153/D8 — the npm
  package's location records the owner. Proposed as an additive `locations[].ownedBy` field
  (`"npm-1:8.19.4-1.module+el8.9.0+..."`), so the service can show "this is Red Hat's bundled
  npm; the RPM's own advisory is the one to act on" and de-duplicate against the RPM finding by
  CVE. **Open for the user:** include `ownedBy` in this increment (schema bump, additive) or
  defer it.

**Go binary probe.**
- Directories, fixed: `usr/bin`, `usr/local/bin`, `bin`, `sbin`, `usr/sbin`, `usr/libexec`,
  `usr/local/sbin` — direct children only, no recursion.
- Candidates: regular files with an execute bit and size ≥ 1 KiB. The first four bytes are read
  through the layer stream; a non-ELF file is skipped without being read further (a new sniffing
  hook on `collect`'s entry read — the one primitive change, so `/usr/bin/bash` costs four bytes,
  not its whole size). An ELF file is read whole under D112's per-file and per-scan limits and
  handed to `debug/buildinfo.Read`; a non-Go ELF is skipped silently (it is not a package).
- A Go binary yields what `assay scan file:<binary>` yields today: the main module, each
  dependency module at its version, and the Go standard library at the toolchain version, keyed
  `Go`, located at the binary's path. `gobinary.Parse` gains a bytes entry point; the `file:`
  path keeps its own.
- A `(devel)` main version (two of the three measured binaries; archlinux's `captree` carries no
  main module at all) is **not a component** for the probe — shipped rule, after the branch's
  differential dispatch showed it adding one `targetIncomplete` per Go binary on three targets:
  the binary is identified by the OS package that installed it, and its dependencies and stdlib
  are what the probe contributes. The `file:` path keeps counting it (D36).

**Budget.** No new limit. The probes read under `MaxFileBytes` and `MaxScanBytes` like every
other image read, and exceeding either is exit 2 as D112 says. Measured: the largest Go binary
is 7 MB and the whole ubi8n18 tree is 236 small files, so the budget is nowhere near; a hostile
image that fills `/usr/bin` with 2 GiB of Go binaries fails the scan, which is D112's rule for
every other hostile shape.

**Disclosure.** `inventoryScope.applicationPackages` keeps its three values (D111) but gains an
additive sibling, `inventoryScope.applicationScope[]`, one record per application ecosystem
the image path knows about: `{ "ecosystem": "npm", "state": "read", "roots": [...] }`,
`{ "ecosystem": "Go", "state": "read", "roots": [...] }`, `{ "ecosystem": "PyPI", "state":
"not-read" }`, `{ "ecosystem": "Maven", "state": "not-read" }`. **Open for the user:** what
`applicationPackages` itself says once the probes run — `read` (true of npm/Go, false of
Python/Java), `not-read` (now false), or a fourth value `partial`. A fourth value changes the
meaning of an existing field and is a breaking bump under `docs/compatibility.md`; the
recommendation is `partial` with the bump, because a consumer switching on the three values
today would otherwise be told either too much or too little. D141's stderr note and the SARIF
`assay/inventory-scope` result say "read: npm (3 roots), Go (7 bin dirs); not read: Python,
Java, node_modules elsewhere, Go binaries elsewhere" instead of "not checked".

**Differential (D93/D117).** `inventoriedTypes` in `cmd/scandiff` gains `npm` and `go-module`
(and grype's `go-module` spelling for stdlib). The three `maxGrypeOnlyApp` seeds that exist for
those types (ubi8n18 npm 82, bci156 go-module 92, cleanstart-postgres go-module 2) are removed
in the same PR, and ubi8n18/bci156/cleanstart floors (`maxFindings`, `maxAssayOnlyFixed`) are
re-seeded only where the branch's own differential dispatch showed a breach: archlinux
(`maxFindings` 44 → 106, `maxAssayOnlyFixed` 25 → 84 for captree's Go stdlib findings); ubi8n18,
bci156 and cleanstart held their floors. Measured on that dispatch: ubi8n18 grype-only 41 → 0
(the three RPM-owned CVEs now agree on both names), bci156 47 → 0, cleanstart 1 → 0.

**Directory scans are not changed.** `dir:` prunes `node_modules` (D26: a checkout's installed
tree is not its declared dependencies). The image probe reads installed trees because an image
has no lockfile to prefer; DESIGN.md's application-packages bullet states the asymmetry.

## Out of scope

Python `dist-info`/`egg-info`, jars inside images, `node_modules` outside the three roots, Go
binaries outside the seven directories, a whole-tree walk, configurable roots, VEX scoping
beyond what D121/D124 already give an image's packages.

## Tests (caller first, CLAUDE.md)

1. `Run` on a synthesized image tar holding `usr/lib/node_modules/npm/package.json` and a nested
   `node_modules/npm/node_modules/minimatch/package.json`, with a database advisory on
   `minimatch`: the finding is reported under `npm` with the nested path, and `inventoryScope`
   says npm read, PyPI not-read. Delete the probe call: red.
2. `Run` on an image with a Go binary built by the test (as `gobinary`'s tests build one) in
   `usr/bin/`, and a database advisory on its stdlib version: finding under `Go`; the same
   binary under `opt/tool/bin/` yields nothing and `applicationScope` says Go read with the
   seven roots. A non-ELF executable in `usr/bin` is never read past four bytes (assert through
   the D112 byte counter).
3. `package.json` without a version → counted skip in `summary.notEvaluated`'s cause list, no
   package.
4. The D141 note and SARIF result carry the read/not-read lists; the directory path still
   emits no `inventoryScope`.
5. `cmd/scandiff`: a committed-targets test that an npm or go-module `maxGrypeOnlyApp` ceiling is
   refused once the types are inventoried.
6. Mutation round after commit; each probe's call site deleted once.

## Docs in the same PR

Roadmap D160 (EN/KO) revising D70 with the measurement; D111 and D141 addenda; D117 addendum;
`docs/compatibility.md` schema bump; CHANGELOG; DESIGN.md's "Application packages inside an
image" bullet and README's "8 language ecosystems" bullet; the deferred entry marked revisited
(Python/Java remain its open half); `CLAUDE.md`'s provider/scan paragraph.
