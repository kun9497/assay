# Deferred decisions

*English · [한국어](deferred-decisions.ko.md)*

Everything here was considered and postponed on purpose — none of it was overlooked.
Each entry records why it was deferred, what should trigger revisiting it, and any
groundwork already in place so that picking it up later stays cheap.

Read alongside the Architecture section of the [README](../README.md).

---

## Deferred work

### The Docker daemon as an image source

`assay` reads images from a registry, a `docker save` tarball, and an OCI layout directory.
It does not talk to the Docker daemon.

**Why deferred.** Measured: importing `go-containerregistry/pkg/v1/daemon` takes the linked
dependency count from **9 modules and 46 packages to 27 and 114** — it pulls in the moby
client and its transitive tree. That is a large increase for a vulnerability scanner, whose
own dependency graph is part of what it asks users to trust, in exchange for the one source
that has a workaround: an image already present locally reaches `assay` through
`docker save`, which the tarball source reads.

**Revisit when** someone has an image they cannot `docker save` — a large one where the
round trip through disk is the bottleneck is the realistic case — or when the daemon
package's dependency tree shrinks.

**Groundwork.** `source.Open` dispatches on a scheme prefix, so a `docker:` prefix and one
more case is the whole change. Nothing downstream of `source.Image` knows where layers came
from.

### ~~Failing a scan when coverage is partial~~ — resolved in slice 4

`--fail-on-incomplete` exits **2** when any package went unevaluated or any check could not
be completed. Exit 2 rather than 1 because D11 already reserves it for a result that cannot
be trusted, and that is exactly what partial coverage produces; it therefore also beats
`--fail-on` when both apply.

It fires on `NotEvaluated > 0 || IncompleteChecks > 0` rather than on the first count alone.
The narrow reading was tried and rejected on a built case: a scan where every package is
checked but one advisory cannot be judged prints "this is NOT a clean result" and would have
exited 0 with the flag set — the report contradicting the verdict, which `Summary`'s own doc
comment forbids.

The gate is opt-in, so the default behaviour is unchanged: uncovered packages are still
counted and named under "Not evaluated" and a scan that does not ask for the gate still
exits on findings alone. The objection that deferred this — one unparseable version breaking
a build — is answered by making it a flag rather than the default.

---

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
`Advisory.Aliases` plus `Advisory.Upstream` carry the CVE↔KVE mapping the join relies on —
both, because OSV 1.7 puts the CVE link in `upstream` and reading only one field makes the
join fail silently (D3).

---

### Malicious-package reports (`MAL-*`)

OSV carries `MAL-*` records — reports that a package **is** malware, not that it contains a
vulnerability. They are dropped at ingestion (D15).

**Why deferred.** Not because they are unimportant — an actively malicious dependency is
more urgent than most CVEs — but because they are a **different finding class** and slice 1
is not the place to design a second one. Measured against 4,000 sampled records:

- **No severity, ever.** Zero of 4,000 carried a `severity` field, so `--fail-on high` has
  nothing to compare against.
- **No fix, ever.** One of 4,000 had a `fixed` event; the rest are `{"introduced": "0"}`
  with no upper bound, meaning *every* version is malicious. There is no "upgrade to 1.2.4"
  to report.
- **Volume.** 216,865 of npm's 223,869 records. Ingesting them takes the slice 1 database
  from ~86 MB to ~430 MB.

**What supporting them properly would mean.** The verdict is categorically different — not
"a vulnerable version is installed, upgrade it" but "this package is malware, remove it and
assume compromise." That implies:

- A separate finding class with its own presentation, not a severity row in the CVE table
- Its own gating, since severity-based `--fail-on` cannot express it. A malicious package
  arguably fails the build unconditionally
- Surfacing `database_specific.iocs` where present — indicators such as attacker-controlled
  domains. This is incident-response data with no analogue in a CVE finding: it tells you
  what to search your egress logs for. Note it is sparse; a `MAL-2024-*` sample carried none
- Handling `withdrawn` records, which appear here at a higher rate than in vulnerability
  data (52 of 4,000 sampled)

**Revisit when.** Slice 4 has established how findings are reported, so a second class has
something to slot into. Worth pairing with the design work rather than bolting on.

**Groundwork.** `Advisory.Kind` is stored from slice 1 onward, so enabling this is a
provider filter change rather than a schema change. `withdrawn` filtering (D16) already
applies to both classes.

*Note: the upstream source is `ossf/malicious-packages`, aggregating findings from vendors
such as Checkmarx. Provenance is in `credits`.*

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

### SARIF output

`--output json` is assay's own schema, versioned and golden-tested. SARIF is the format
GitHub code scanning and most CI dashboards ingest, so it is what makes findings show up
next to the code rather than in a log.

**Why deferred.** SARIF is a large specification and only a narrow slice of it is relevant
here — `runs[].results[]` with a rule per advisory and a physical location per package. The
work is not the mapping, it is deciding what a "location" means for a package that came out
of a container layer: a purl is not a file range, and the natural answer (the package
database path plus the layer digest) is already carried in the JSON output but is not what a
code-scanning UI expects to highlight. Getting that wrong produces findings pinned to the
wrong line of the wrong file, which is worse than no SARIF at all.

**Revisit when** someone wants assay's results in GitHub code scanning, or when directory
and binary scanning (slice ③) land — a finding in a checked-out source tree has a real file
path, which removes the hard part of the mapping.

**Groundwork.** `internal/report/json.go` already assembles every field SARIF needs
(advisory ID, aliases, severity band and score, package name and version, purl, the source
package, and the layer digest and path of every location) from a single `Summarize` call, so
a SARIF renderer is a third `Reporter` over the same data rather than a new traversal.

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

**Severity normalization.** OSV carries severity as CVSS vectors — the Go dump contains both
`CVSS_V3` and `CVSS_V4` — and **half of all records carry none at all** (4,335 of 8,617).
`--fail-on` needs a single band from that, and absent severity must never become "low". See
D17; this is common enough that it is a main path, not error handling.

**Redundant `versions[]` arrays.** OSV records often enumerate every affected version
alongside the `ranges` that already describe them, repeated per distro release. A sampled
Alpine record spent most of its 4 KB on four copies of a ~90-entry version list. Storing
them losslessly (D13) is the default, but they may dominate database size once distro data
lands. Where `ranges` is present the enumeration is derivable; where it is absent it is the
only matching data, so any pruning must be conditional. Measure during slice 2 before
deciding.

---

## Assumptions

Recorded because design decisions rest on them.

### Resolved — measured 2026-07-29

| Assumption | Outcome |
|---|---|
| OSV record volumes are in the hundreds of thousands, not millions | **Confirmed.** 257,075 records across slice 1 ecosystems, 28,613 after excluding `MAL-*`. bbolt and JSON hold, with headroom either way. Full numbers in the roadmap's *Measured data volumes*. |
| OSV's RHEL-family coverage is thinner than Alpine/Debian | **Wrong as stated.** A `Red Hat` ecosystem exists (25 MB compressed). Whether it is backport-aware enough for accurate matching is still open — but the data is not absent. |
| Distro advisories are source-keyed for Debian and RHEL | **True but understated.** Alpine is source-keyed too (`purl` carries `?arch=source`), so indirect matching is needed from slice 2 rather than later (D8). |
| The CVE link for the KISA join lives in `aliases` | **Wrong.** OSV 1.7 records use `upstream`; a sampled Alpine record had `upstream` and no `aliases`. Both fields must be read (D3). |

### Still open

| Assumption | What depends on it |
|---|---|
| KNVD offers a machine-readable API, and its terms permit redistribution | The entire KISA provider; scraping would change its difficulty completely |
| OSV's Red Hat data is backport-aware enough for accurate RHEL matching | Whether RHEL support is viable through OSV at all, or needs Red Hat's own feed |
| grype's default database-age behaviour is a warning, with enforcement opt-in | Only referenced as prior art, not depended on |
