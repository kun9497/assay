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
`Advisory.Aliases` plus `Advisory.Upstream` are read together — both, because OSV 1.7 puts the
CVE link in `upstream` and reading only one field makes a join fail silently (D3).

That pair was originally justified as carrying "the CVE↔KVE mapping". It does not: measured
2026-08-02, KNVD's public search returns nothing for `KVE-2024-0771` or even the bare string
`KVE`, while the same search finds a CVE (control). KVE numbers are real and third parties
cite them, but no public record resolves one, so there is no KVE side to map to. D3 is
unaffected — reading both fields was independently confirmed necessary inside OSV itself, Go
records carrying the CVE in `aliases` and Alpine records in `upstream`.

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
verified as sufficient (see Assumptions).

---

### Does an unrated source count as disagreeing?

The table marks a finding with `*` and footnotes "sources disagree on severity" whenever its
sources landed on different bands. An UNRATED source currently counts as one of those bands.

**Why deferred.** D17 says `unknown` sits outside the ordering: it means nobody assessed
this, so arguably a source with no opinion has not disagreed with one that has. The current
behaviour was harmless while it was rare. D27 makes it the norm — NVD rates ~93% of CVEs
while about half of OSV's records carry no severity at all, so most annotated findings now
get the marker, and a marker that fires on almost everything stops carrying information.

Left alone anyway, because it fails in the safe direction: it over-marks rather than
under-marks, and the cost is noise rather than a missed vulnerability. Narrowing what the
marker means is a change to the report's contract — what a reader is being told when they see
a `*` — and that is a decision, not a defect to quietly fix during a review pass.

**Revisit when.** The first scan against a full NVD-enabled database, where the real ratio of
marked to unmarked findings is visible rather than estimated. If nearly every row carries a
`*`, the marker has already stopped working and the decision makes itself.

**Groundwork.** `sourcesDisagree` is one function in `internal/report/table.go`, and its
tests name the intended semantics explicitly, so the change is small either way.

---

### Publishing the database as an OCI artifact

Users build the database locally with `assay db update`.

**Why deferred.** Prebuilt artifacts matter for distributing to other people and for CI
runs where rebuilding is too slow — neither applies yet. This is also infrastructure work
(scheduled build workflow, registry auth, version tagging) rather than scanner work, and
would mean building a distribution pipeline before the scanner runs.

**Revisit when.** ~~There are users beyond the author, or CI rebuild time becomes the
bottleneck.~~ **Fired 2026-08-03, on the second condition.**

Measured while building D27: a full NVD sync is about seven hours, because NVD generates each
2,000-record page in 114–136 seconds and neither compression nor a smaller page changes the
total. Local building was affordable while OSV was the only source — a few minutes of archive
download. It is not affordable now, and it is not a constant anyone can tune away.

That makes this the next slice rather than a someday. The shape is grype's and trivy's: a
builder runs the seven hours once and layers daily deltas on top, publishes the built
database, and `assay db update` pulls it. Note that layering is the part that does not exist
yet: `Update` rebuilds from empty, so D27's `Since` bounds one build rather than extending the
last one, and this slice is what makes a real delta possible. A scan still fetches nothing
(D14), and registry distribution brings mirroring and air-gapped operation with it.

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

### Flags on the `db` subcommands

`assay db status --output json` exits 0 and prints the human table; `assay db status
--bogus` does the same. The `db` arm has never parsed flags, so anything after the
subcommand is ignored.

**Why deferred.** It is pre-existing rather than new, but `--output json` now exists as a
real concept on `scan`, so "typed a flag, flag ignored" became reachable by someone
reasonably assuming it is global — the exact shape `parseScanArgs` rejects on the scan side.
The fix is not just rejecting unknown arguments: it is deciding whether `--output json`
should mean something for `db status` (a machine-readable coverage and freshness report is
plausibly useful in CI) before making it an error to ask for it.

**Revisit when** anything needs `db status` output in a pipeline, or sooner if a second
subcommand grows a flag — two arms silently ignoring arguments is a pattern rather than an
oversight.

**Groundwork.** `parseScanArgs` already shows the shape: reject the unrecognised rather than
skip it, and reject a repeat rather than take the last.

---

### What a directory scan does not read

`vendor/`, `go.sum`, and the module cache. A directory scan reads `go.mod` and stops (D23).

**Why deferred.** Each answers a different question and none is free. `vendor/` is the most
tempting — `vendor/modules.txt` lists the exact modules a vendored build uses, which is
closer to the truth than `go.mod` — but it exists only in vendored repositories, so it would
make the accuracy of a directory scan depend on a project layout the user did not choose for
our benefit. `go.sum` holds every version ever *considered*, not the ones selected, so it
over-reports by a wide margin. Reading the module cache to compute a real build list means
reimplementing minimal version selection, which is a different project.

**Revisit when** someone scans a vendored repository and finds the answer thinner than they
expected. `vendor/modules.txt` is the cheap one of the three: exact when present, and the
honest shape is "use it when it is there, say so when it is not".

**Groundwork.** `gomod.Parse` takes a directory, not a file, so a second source inside that
directory is an addition rather than a signature change.

---

### npm and PyPI directory scanning

`package-lock.json` and `poetry.lock` / `requirements.txt`, the same way `go.mod` is read now.

**No longer deferred — promoted to slice ⑥ on 2026-08-03, and it was not a feature gap.**
Measured: a directory holding `go.mod` and `package-lock.json` reports 3 findings and
`0 not evaluated` where the same packages as an SBOM report 27. The deferral above reasoned
that a second `Cataloger` "proves less than the first did", which was true of the cataloger
and false of the scan — nothing disclosed that the other manifests existed, so the omission
was invisible to the skip counter D20 built to make omissions visible. Recorded as D26.

The revisit trigger ("someone scans a JavaScript or Python project") was the wrong trigger:
it required a user to appear before the defect could be noticed, when the defect was
reachable by reading the dispatch in `scancmd.go`. A trigger that waits for a report is the
wrong shape for a silent failure.

`requirements.txt` stays out. It is not a lockfile — `Django>=3.2` is a constraint, not a
version — and it needs its own decision (see below).

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

**The revisit trigger has fired, and it did not help as much as expected.** Slice ③ landed,
so a directory scan is now possible — but it reads `go.mod` and reports modules, not source
locations. The finding's location is still `<dir>/go.mod`, a single file, and a binary scan's
is the binary. Neither is the "line of code that introduced this dependency" a code-scanning
UI wants to highlight. What actually removes the obstacle is a cataloger that knows where in
the tree a dependency is declared, which nothing here needs yet.

**Revisit when** someone wants assay's results in GitHub code scanning. That is now the only
trigger; the filesystem one has been discharged.

**Groundwork.** `internal/report/json.go` already assembles every field SARIF needs
(advisory ID, aliases, severity band and score, package name and version, purl, the source
package, and the layer digest and path of every location) from a single `Summarize` call, so
a SARIF renderer is a third `Reporter` over the same data rather than a new traversal.

---

### Ingesting NVD as a rating source

D25 made a finding carry every source's rating rather than one winner. NVD is the obvious
next source: it rates nearly everything, and the gap D25 exposes is that 14 of a real Django
scan's 19 findings are rated by GHSA alone while PYSEC supplies no severity at all.

**Groundwork.** A new provider writes `Advisory.Database = "NVD"` and the
matcher, the gate and all three renderers pick it up with no change — that was the point of
building D25 as a mechanism rather than special-casing two source names. Adding NVD is a
provider, not a redesign.

**Why deferred.** The cost is in the data, not the code. NVD is a different shape from OSV
(CPE match ranges, not purl-keyed `affected[]`), so it needs its own normalization into the
OSV shape D1 requires, and CPE-to-purl matching is its own well-known problem — the place
grype spends much of its complexity. The feed also has a request-rate policy and an API-key
regime that the current "fetch archives over HTTPS" provider shape does not model.

There is also a correctness question worth settling first. On the Django differential, grype
matched assay's GHSA rating on 19 of 19 findings and assay's PYSEC rating on 1 of 15, which
is consistent both with grype taking the highest and with grype following GHSA — the sample
cannot separate them because PYSEC rates none of them. NVD would supply the third opinion
that tells those apart, but it would also change what `--fail-on` fires on for a large number
of currently-unrated findings, which is a verdict change, not an enrichment.

**Revisit when** a scan's unrated findings are the thing blocking a decision — concretely,
when `--fail-on-unknown` is being turned on and immediately becomes noise, which is the
signal that "nobody rated this" has stopped being informative. At that point measure first:
how many of the unrated findings NVD actually rates, and how many verdicts flip.

---

**Measured 2026-08-03.** The entry above said to measure first; this is that measurement,
against a schema-5 database of 32,046 advisories and NVD's 2.0 API.

*What NVD would add, as a severity source:*

| | |
|---|---|
| advisories assay rates `unknown` | **8,029 (25%)** |
| of those, carrying a CVE NVD could be asked about | 7,021 |
| of those, carrying **no CVE at all** | **1,008 (13%)** |
| random sample of unrated CVEs queried | 60 |
| known to NVD | 57 (95%) |
| carrying a CVSS score | **56 (93%)**, 95% CI 84–97% |
| scoring **high or critical** | **29 (48%)**, 95% CI 36–61% |

Nearly half of what assay reports as `unknown` NVD rates high or critical. Scanning assay's
own binary makes this concrete: all three findings are unrated, so `--fail-on low` — the
lowest threshold there is — exits 0. NVD rates two of them 7.8 (high) and 5.3 (medium); the
third carries no CVE and would stay unknown. That is the 13% arriving in a three-finding scan.

*What NVD would add as an independent matching source — the part that does not work:*

NVD keys on `vendor:product`, and for a language package that pair is a curated string no
purl can derive: `pkg:golang/gopkg.in/yaml.v3` is `cpe:2.3:a:yaml_project:yaml:...` and
`django` splits across two vendors (`djangoproject` and `django_project`). So a full provider
needs a purl→CPE dictionary, which is where grype spends much of its complexity.

That dictionary can in principle be *learned* rather than written, by joining OSV and NVD on
the CVE they share — 10,596 (ecosystem, package) pairs are reachable that way. Sampling 50 of
them and resolving each against NVD:

| ecosystem | rows teaching a trustworthy mapping |
|---|---|
| Alpine | 17 of 20 (85%) |
| PyPI | 5 of 7 (71%) |
| npm | 7 of 14 (50%) |
| **Go** | **1 of 9 (11%)** |

24% of the sampled CVEs carry no CPE at all, and **those rows are not awaiting analysis, they
are `Deferred`** — NVD's status for records it has decided not to enrich (9 of the 12, against
2 `Awaiting Analysis`). Five of Go's six CPE-less rows are `Deferred`. The gap is a decision,
not a backlog, so it will not close by waiting.

**The conclusion the numbers force.** NVD is a strong *severity* source and a weak *matching*
source, and it is weakest exactly where assay's unrated population is largest: Go supplies
4,125 of the 8,029 unrated advisories and is the one ecosystem whose CPEs cannot be learned.
Alpine maps best, and is the one place NVD's version ranges would be wrong anyway, because
distros backport fixes — the hazard already recorded under RHEL-family support.

**Still deferred, with the trigger replaced.** The old trigger ("`--fail-on-unknown` becomes
noise") asked the wrong question: the problem is not noise, it is that half of assay's
`unknown` findings are high or critical and trip no gate at all. What is *not* yet decided is
which shape to build, and that is a D decision, not a deferral: enrichment by CVE is small and
supported by the evidence, an independent CPE matcher is large and contradicted by it.

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

### Resolved — measured 2026-08-02

| Assumption | Outcome |
|---|---|
| KNVD offers a machine-readable API, and its terms permit redistribution | **Both no, and a third answer matters more.** Two documented RSS feeds exist and each returns only the latest 10 items; the SPA's own POST API is undocumented and the portal's previous deep links now 500, so nothing there is a stable contract. The footer reads `Copyright(C) 2026 KISA. All rights reserved.` with no 공공누리 mark. But the finding that decides the slice is coverage: **173 records total**, all Korean domestic commercial software. See the roadmap's Slice 5. |

### Resolved — measured 2026-08-03

| Assumption | Outcome |
|---|---|
| Sources disagree about the fixed version in ~90% of multi-record groups (D25's own "152 of 169") | **Wrong as stated, and not reproducible.** Re-measured over the whole database: 2,210 of 8,893 (25%), 510 of 4,488 (11%) for `GHSA`+`PYSEC`, and 0 of 15 on the Django scan D25 cites as its example. The original scope was "the packages a real scan touches", which is not recoverable without that package list, so the two may not be measuring the same thing. Nothing in D25 rests on it — a rating carries its own fixed version because that source's remediation belongs to that source, agreement or not. Recorded beside the original in the roadmap. |
| Sources disagree about severity often enough to matter | **Confirmed, with the mechanism clarified.** 5,693 of 8,893 multi-record groups land on different bands — but 5,423 of those are one source rating what another leaves unrated, and only 306 are two rated sources scoring differently. The aggregate's hard case is `unknown`, not conflicting scores, which is why D17 keeping `unknown` outside the ordering is what makes it work. |

### Still open

| Assumption | What depends on it |
|---|---|
| OSV's Red Hat data is backport-aware enough for accurate RHEL matching | Whether RHEL support is viable through OSV at all, or needs Red Hat's own feed |
| grype's default database-age behaviour is a warning, with enforcement opt-in | Only referenced as prior art, not depended on |
