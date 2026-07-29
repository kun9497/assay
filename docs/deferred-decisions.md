# Deferred decisions

Everything here was considered and postponed on purpose — none of it was overlooked.
Each entry records why it was deferred, what should trigger revisiting it, and any
groundwork already in place so that picking it up later stays cheap.

Read alongside the Architecture section of the [README](../README.md).

---

## Deferred work

### KISA/KNVD as an independent matching source

Currently scoped as **enrichment only**: a finding already matched through OSV picks up
its Korean description, KISA severity, and KNVD link by joining on CVE ID. KVE entries do
not produce findings of their own.

**Why deferred.** Many KNVD advisories describe domestic commercial software in prose
("한글 2020 버전 x 이하") with no ecosystem, no purl, and no package name. Matching those
is CPE-style *product* identification, not package matching — a second matcher plus a
cataloger that can report installed products rather than packages. It is also a poor fit
for the current targets: container images and source trees do not contain 한컴오피스.

**Revisit when.** Targets expand to hosts or workstations, or when KNVD coverage of
server-side and open-source software proves substantial enough to matter on its own.

**Groundwork.** `Advisory.Source` records which provider supplied a record, and
`Advisory.Aliases` already carries the CVE↔KVE mapping the join relies on.

---

### Debian and Ubuntu package support

First container slice covers Alpine only.

**Why deferred.** Each distro costs a `Comparer` plus an ecosystem mapping. Alpine's
version scheme (`-rN` suffixes) is the simplest of the three, so it proves the whole OS
package path — purl → distro release → `Alpine:vX.Y` lookup → apk comparison → finding —
at the lowest cost. Debian's `epoch:upstream-revision` scheme and Ubuntu's ESM/backport
representation are additional work on a path already known to function.

**Revisit when.** The Alpine path is working end to end.

**Groundwork.** `Package.Source` exists for indirect matching, and dpkg's
`/var/lib/dpkg/status` exposes the `Source:` field needed to populate it.

---

### RHEL-family package support

**Why deferred.** Two independent obstacles. Reading the package list means parsing
`/var/lib/rpm/*`, a binary database — BerkeleyDB on older releases, SQLite on RHEL 9+ —
which needs a pure-Go rpmdb parser. Separately, Red Hat backports fixes, so upstream
version comparison produces false positives without Red Hat's own fixed-version data.

**Revisit when.** Debian/Ubuntu are working, and OSV's RHEL-family coverage has been
verified as sufficient (see Unverified assumptions).

---

### Publishing the database as an OCI artifact

Users build the database locally with `assay db update`.

**Why deferred.** Prebuilt artifacts matter for distributing to other people and for CI
runs where rebuilding is too slow — neither applies yet. This is also infrastructure work
(scheduled build workflow, registry auth, version tagging) rather than scanner work, and
would mean building a distribution pipeline before the scanner runs.

**Revisit when.** There are users beyond the author, or CI rebuild time becomes the
bottleneck.

**Groundwork.** Provider source URLs are configuration rather than constants, so adding a
pull path later does not disturb the interface.

*Borrowed from trivy, which distributes `trivy-db` via `ghcr.io`. Registry distribution
gets mirroring, auth, and air-gapped operation for free.*

---

### Splitting KISA data into a separate artifact

**Why deferred.** Depends entirely on the OCI artifact decision above — "separate
artifact" presupposes artifacts. Enrichment data is a `CVE ID → description/severity`
mapping, likely too small to be worth splitting.

**Revisit when.** Database artifacts exist, and KISA data grows enough that users who do
not need it are paying a real cost.

**Groundwork.** `Advisory.Source` makes partitioning by provider straightforward.

*Borrowed from trivy's separate `trivy-java-db`.*

---

### Committing collected upstream data to git

**Why deferred.** The value is an audit trail for data that changes silently, which
matters most for public-sector sources. While KISA is enrichment-only, a silent change
alters displayed text but not verdicts. It also needs a separate repository and
commit automation.

**Revisit when.** KISA becomes an independent matching source, at which point silent
upstream changes start moving verdicts.

*Borrowed from `aquasecurity/vuln-list`.*

---

### Database age enforcement

`assay db status` reports each provider's `DataAsOf` as a plain fact. Nothing warns, and
nothing fails.

**Why deferred.** The threshold — how old is too old — is arbitrary without usage data.
Picking 30 days today would be a guess dressed as policy.

**Revisit when.** The tool has been used enough to know what staleness looks like in
practice. Planned as `--db-max-age` returning exit code 2.

**Groundwork.** This is the deferral with the most preparation, because the parts that are
expensive to add later are already in:

- `Provenance.DataAsOf` is recorded per provider at build time. Age is judged from
  *upstream* data time, never from local build time — a mirror serving a three-month-old
  snapshot must not look fresh just because it was fetched today.
- Exit code precedence is fixed as contract: **2 > 1 > 0**. An untrustworthy result
  outranks the content of the result.

Both would require a database rebuild or a breaking CLI change to retrofit.

---

### Value encoding beyond JSON

Advisories are stored as JSON blobs in bbolt.

**Why deferred.** For a few hundred lookups per scan, bbolt reads are microseconds and
JSON unmarshalling dominates — still tens of milliseconds total. Optimizing before
measuring is premature.

**Revisit when.** Record counts land an order of magnitude above the current estimate, or
profiling shows decoding dominating scan time. `Store` is a single-method interface, so
the encoding is fully hidden behind it.

---

### SPDX ingestion

CycloneDX first. SPDX is a second parser against an already-proven pipeline, adding no new
architecture.

---

### VEX and ignore rules

Suppressing known-irrelevant findings. Both grype and trivy support this, and it becomes
necessary once the tool is used against real projects with accepted risks. No architectural
preparation needed — it is a filter between `Matcher` and `Reporter`.

---

### Binary support beyond Go

Go first, via the standard library's `debug/buildinfo`, which returns the module list
directly. Java is the natural second (`MANIFEST.MF`, `pom.properties`).

**Why deferred.** Binary support is not one feature — it is one feature per language, and
they differ enormously. Rust works only when built with `cargo-auditable`. Stripped C/C++
leaves nothing reliable; recovering dependencies means string heuristics and symbol
matching, with false-positive rates that make it a research problem rather than a task.

Support is decided per language rather than promised as a category.

---

## Known hazards

Not deferred decisions — traps to handle when the relevant code is written.

**Atomic database replacement on Windows.** `db update` builds into a temporary file and
renames over the live database, so a concurrent scan never sees a partial write. On
Windows, rename fails if the target is open. Needs explicit handling; do not assume POSIX
rename semantics.

**Distro release missing from third-party SBOMs.** Matching an OS package needs the distro
release (`Alpine:v3.19`), which a purl does not carry. syft records it in CycloneDX
properties (`syft:distro:id`, `syft:distro:versionID`), but that is a syft extension, not
part of the CycloneDX specification. SBOMs from other tools may omit it entirely, leaving
OS packages unmatchable. Scanning images directly avoids this — `/etc/os-release` is read
first-hand — but the SBOM ingestion path must degrade honestly: report the packages as
skipped, never silently treat them as clean.

**Severity normalization.** OSV carries severity as CVSS vectors, which may be v2, v3.x,
or v4, and some records carry none. `--fail-on` needs a single band from that. Absent
severity must not silently become "low".

---

## Unverified assumptions

Recorded because design decisions rest on them. Each was reasoned from memory rather than
checked, and should be confirmed before the dependent work starts.

| Assumption | What depends on it |
|---|---|
| OSV per-ecosystem record volumes are in the hundreds of thousands, not millions | Choice of bbolt and JSON value encoding |
| KNVD offers a machine-readable API, and its terms permit redistribution | The entire KISA provider; scraping would change its difficulty completely |
| OSV's RHEL-family coverage is thinner than its Alpine/Debian coverage | Ordering of distro support |
| grype's default database-age behaviour is a warning, with enforcement opt-in | Only referenced as prior art, not depended on |
