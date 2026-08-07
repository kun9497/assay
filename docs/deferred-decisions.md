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

### ~~Debian package support~~ — resolved in slice ⑪ (D40–D42)

First container slice covers Alpine only.

**Why deferred.** Each distro costs a `Comparer` plus an ecosystem mapping. Alpine's
version scheme (`-rN` suffixes) is the simplest of the three, so it proves the whole OS
package path — purl → distro release → `Alpine:vX.Y` lookup → apk comparison → finding —
at the lowest cost. Debian's `epoch:upstream-revision` scheme and Ubuntu's ESM/backport
representation are additional work on a path already known to function.

**Resolved 2026-08-07 as D40–D42.** The trigger fired, and the decisive question — whether
Debian has Red Hat's backport problem — was answered by measurement: it does not. Debian
encodes the backport in the version (`7.74.0-1.3+deb11u10`), and 169,282 (CVE, source,
release) triples joined against Debian's own tracker disagree zero times.

The groundwork held. `Package.Source` already carried a `Version` field, which turned out to
be exactly what D41 needed — a binNMU rebuilds a binary without touching the source, so 13–15%
of Debian packages carry a source version that differs from the binary one, and OSV's
advisories are written against the source.

**Ubuntu did NOT come with it**, and now has its own entry below.

---

### Ubuntu package support

**Why deferred.** Not the version scheme — the dpkg comparer D40 added handles Ubuntu
revisions (`2.4.4-2ubuntu17.10`) unchanged. Two other things.

OSV keys Ubuntu as `Ubuntu:24.04:LTS`, and its Pro and FIPS lineages —
`Ubuntu:Pro:FIPS-updates:18.04:LTS`, `Ubuntu:Pro:20.04:LTS` — describe the **same release**. A
release-only ecosystem key cannot separate them, so a scan of an ESM-patched system would
match the non-ESM lineage's fixed versions and report it vulnerable. That is a systematic
false positive, and D6's "the release is in the key" is not enough on its own; the key has to
carry the lineage too, which is a decision about what an ecosystem key means rather than a
line in the distro mapping.

The corpus is also 5.8 GB unpacked against Debian's 383 MB, so the provider would have to
stream and discard `versions[]` rather than parsing records whole.

**Revisit when** the lineage question has an answer. Measuring first is the cheap step: how
many packages in a real Ubuntu image are covered by more than one lineage, and how often the
fixed versions differ between them.

**Groundwork.** The comparer, the dpkg cataloger and the `Source:` handling are all done and
ecosystem-agnostic. What is missing is the key.

---

### ~~RHEL-family package support~~ — resolved across slices ⓫–⓭ (D43–D50)

**Why deferred.** Two independent obstacles were recorded. Reading the package list means
parsing `/var/lib/rpm/*`, a binary database — BerkeleyDB on older releases, SQLite on RHEL 9+
— which needs a pure-Go rpmdb parser. Separately, Red Hat backports fixes, so upstream
version comparison produces false positives without Red Hat's own fixed-version data.

**The second obstacle was wrong as written, measured 2026-08-07.** Red Hat's OSV export
carries native NEVRAs, not upstream versions. All 588,150 fixed events across the 21,851
records carry both an epoch and a release; 95.8% carry `.elN` and the residual are RHEL 3–5
records in the older uppercase form, which also carry both. There is no upstream-shaped fixed
version anywhere in the archive.

```
RHSA-2024:4312  CVE-2024-6387 (regreSSHion; upstream fixed in 9.8p1)
  ecosystem "Red Hat:enterprise_linux:9::baseos"  package "openssh"
  fixed: "0:8.7p1-38.el9_4.1"
```

The upstream version is untouched by the fix and the whole backport lives in the release
field — the same mechanism that let Debian pass its own gate. Checked against a real
`ubi9` image, every patched package reads as fixed: `openssl-libs 1:3.5.5-6.el9_8` against a
maximum advisory fixed of `1:3.5.5-4.el9_8`, and the same for `glibc`, `systemd-libs` and
`libxml2`. The systematic false positive the obstacle predicted does not reproduce.

**The first obstacle is real but cheaper than assumed**, which is why the inventory half
shipped. See D44 — a scanner only ever enumerates the database, so the hash index that makes
rpm's own read-only BerkeleyDB backend 850 lines of C is dead weight.

**Three different obstacles replace the one that was wrong, and they still gate matching:**

- **The OSV Red Hat feed is errata-only.** Zero of the 588,150 affected entries lack a fixed
  version, so "affected, will not fix", "fix deferred" and "out of support scope" cannot be
  expressed at all. Red Hat's CSAF VEX feed carries 62,983 CVEs against OSV's 23,668 —
  **39,372 CVEs exist only in VEX, 19,341 of them from 2023 onwards**, and in two independent
  samples 37–43% of those name a base-OS RPM as `known_affected` with no fix available. A
  scanner built on this feed alone reports every one of them clean. That is the silent
  false-negative class this project exists to avoid, and it is why D43 emits no RHEL findings.
- **The ecosystem key cannot be derived from an image.** 903 distinct keys across mainline,
  `rhel_eus`, `rhel_aus`, `rhel_tus`, `rhel_e4s` and per-minor variants, with repository
  granularity below that (`::baseos`, `::appstream`, `::crb`, `::realtime`, `::nfv`). 53.1% of
  (CVE, package, major) groups span more than one key and 29.7% resolve to a *different* fixed
  version depending on which is chosen. `/etc/os-release` gives the minor version but the
  support channel is a subscription attribute with no filesystem representation. The keys also
  come in five shapes, and RHEL 10 uses the bare three-part form
  (`Red Hat:enterprise_linux:10.2`) that a parser written for the common one drops silently.
  Unrelated products share the namespace (`Red Hat:openstack:10::el7`,
  `Red Hat:jboss_enterprise_application_platform:6`, 9,118 entries), so a prefix match on
  `Red Hat:` pulls them in.
- **The modularity label is absent from the archive.** All 588,150 purls are bare — no
  qualifiers of any kind — and the stream name is not recoverable from the version string,
  which encodes only the platform build and a context hash
  (`1:20.20.2-2.module+el9.6.0+24220+c44c288d`). 19.1% of mainline groups are module-tagged and
  modules cause 69% of the residual fixed-version ambiguity that survives restricting to
  mainline keys. `('CVE-2021-20291', 'buildah', '8')` resolves to two fixed versions from two
  streams of `container-tools`; taking the higher is a systematic false positive and taking the
  lower is a false negative.

**AlmaLinux and Rocky Linux are not the easier path.** Both key on the major version only —
three keys each, derivable from `/etc/os-release` — which is genuinely simpler. Neither
survives the rest:

- **AlmaLinux carries zero `aliases` and zero `upstream` fields** across all 5,494 records.
  Every CVE reference is in `related`, which OSV defines as explicitly *not* an alias. Under D3
  as written, AlmaLinux yields **0 CVEs** and the D25 rating join produces 0 matches. It also
  has no severity data at all (0% CVSS coverage, against Red Hat's ~84%), so under D17 every
  Alma finding would land in `unknown` and never trip `--fail-on`. Reading `related` is a
  semantic change to the join, and therefore its own decision.
- **Rocky Linux's export is too incomplete to ship.** Median 0.29 coverage of Red Hat's runtime
  package set, 83% of shared (CVE, major) groups missing at least one runtime package, only
  `curl` named for CVE-2023-38545 where Red Hat and Alma both name `curl`, `curl-minimal`,
  `libcurl` and `libcurl-minimal` — and **no record whatsoever for CVE-2024-6387**. A
  `rockylinux:` target must exit 2, never exit 0.
- Alma also writes module builds as `module_el8.5.0+119+9a9ec082` where Red Hat and Rocky write
  `module+el8.5.0+12582+56d94c81`, so Alma advisory versions must never be compared against
  RHEL-installed packages. Routing on `/etc/os-release` `ID` (`rhel` / `almalinux` / `rocky`)
  rather than on the `elN` release string is what prevents that.

**Resolved. The inventory landed in ⓫ (D43–D46), the advisory data in ⓬ (D47–D49), and
matching in ⓭ (D48, D50) — `assay scan ubi9` now produces findings, and
`--fail-on-unfixable` gates on the ones nothing can fix.**

**The advisory half was resolved in slice ⓬ (D47–D49).** Red Hat's CSAF VEX feed is
ingested: 67,261 documents yield 28,907 advisories and 1,918,779 affected entries, 1,278,384 of
them with no fix available. It cost no new dependency. See the roadmap's D47–D49 and
the README's slice ⓬.

Note that the "VEX" in *VEX and ignore rules* below is a different thing: that entry is about a
consumer supplying VEX to suppress findings, this one is about a vendor publishing
affectedness.

**Still deferred.** OVAL v2 as a second opinion (it covers RHEL 5–9 and has no RHEL 10, so it
could never be the primary source); AlmaLinux and Rocky, whose objections above are unchanged
and which D50 therefore does not route; and closing the EUS/AUS/E4S divergence rather than
disclosing it, which needs a channel signal no image carries.

---

### Whether the published artifact carries the Red Hat data

**Why deferred.** `REDHAT_ENABLE` is off by default (D49), so `assay db build` produces the
same database it always did unless somebody asks for more, and the publish workflow has not
been changed. What has not been decided is whether the artifact `db update` delivers should
carry it at all.

Measured on this machine, 2026-08-07, both builds from the same sources on the same day:

| | OSV only | with Red Hat VEX |
|---|---|---|
| advisories | 94,122 | 123,029 |
| bbolt file | 512 MiB | **1.00 GiB** |
| build CPU | 126 s | **848 s** |
| wall clock | ~9.5 min | ~24 min |

Both file sizes are exact powers of two because bbolt grows its mmap that way, so they are
allocation sizes rather than bytes of data — the real content is smaller and the ratio between
them is not 2.00. The CPU figure is unambiguous, and it is **6.7×**: streaming and converting
the archive takes 90 seconds, and the rest is bbolt writing 1.9 million affected entries.

**The options are the same three that *Splitting KISA data into a separate artifact* records,
and for a different reason.** KISA is split because it may not be redistributed (D29); this
would be split because most users do not scan RHEL images and a doubled download serves them
nothing. A second artifact, a second tag, or simply leaving it to people who build their own
are all live.

**Revisit when** RHEL matching ships and someone actually wants the data delivered rather than
built. Until then the honest state is that `db update` never carries it and `REDHAT_ENABLE=1
assay db build` is the only way to get it, which is exactly what the flag documents.

**Related hazard.** A 24-minute build is close enough to the six-hour job cap that nothing
breaks today, but it compounds with anything else added to the same run — see *Checkpointing
a long sync*.

---

### The VEX archive lags its own change feed

**Why deferred.** The provider reads the one full archive `archive_latest.txt` names, and
nothing else. Red Hat rebuilds that archive on its own schedule, and individual documents
change in between — so a database built from the archive alone is behind by up to a day, and
sometimes more.

Measured on the ubi9 differential (2026-08-07): grype found 3 findings assay did not, all from
two CVEs whose documents were created on **2026-08-06**, the day after
`csaf_vex_2026-08-05.tar.zst` was built. `changes.csv` timestamps them
`2026-08-06T03:46:10` and `2026-08-06T12:51:52`, `index.txt` lists them, the per-document
endpoint serves them — and neither is in the archive. That is 3 of grype's 418 findings, 0.7%,
and the whole of the divergence between the two tools on that image.

**The mechanism to close it already exists upstream.** `changes.csv` is 3.4 MB and lists every
document with its last-modified timestamp; `index.txt` lists every path. Fetching only the
documents modified after the archive's own date would close the gap for a bounded number of
extra requests. The provider already parses the archive date out of its filename for D12, so
the comparison point is in hand.

**Revisit when** the lag matters more than the requests cost, or when somebody is bitten by a
same-week CVE. Note the interaction with *Checkpointing a long sync*: the delta pass is the
part that would want resuming, not the archive read.

---

### Red Hat's fix state is collapsed to "there is no fix"

**Why deferred.** CSAF distinguishes remediation categories that this provider does not keep.
Archive-wide there are 22,289 `no_fix_planned` and 16,935 `none_available` remediations, and
grype surfaces the same distinction as `wont-fix` versus `not-fixed`. On the ubi9 differential
grype's 415 shared findings split **404 `not-fixed` / 11 `wont-fix`**; assay reports all 415 as
"no fix available".

The two mean different things to a reader. "Red Hat has decided not to fix this" is final and
the only remaining moves are mitigation or removal; "no fix yet" is a reason to watch the CVE.
Collapsing them loses an action, not just a label.

**Why it was not done now.** D48 chose the OSV range shape — an `introduced` event and no
`fixed` one — precisely because it needed no schema change, and that shape has nowhere to put
a reason. Carrying it means either a field on `advisory.Range` or a per-advisory annotation,
and either is a store change that D5 turns into a schema bump and a rebuild.

**Revisit when** the store next changes shape for another reason, so the two land together.

---

### ~~The BerkeleyDB rpm backend~~ — resolved in slice ⓮ (D44)

**Why it was deferred.** RHEL 8, Amazon Linux 2 and their rebuilds keep the database as a
BerkeleyDB hash file (`Packages`, magic `0x00061561`) rather than SQLite. Those images exited 2
with the backend named, which was honest but not support.

**Resolved 2026-08-07.** Roughly 300 lines, no dependency, on D44's reasoning a second time: a
scanner only enumerates, so the hash function is never computed, the bucket array is never
consulted, and the nineteen btree indices beside the file are never opened.

The cost of leaving it was measured before it was closed — grype found **504 findings on a real
ubi8 image where assay found none**, because the format refusal came before any matching. The
reader was then validated against that same image: 183 packages, all 183 shared with syft,
syft's only extras being the two `gpg-pubkey` keyring entries this build filters, and zero
source-name disagreements.

Both inline (`H_KEYDATA`) and off-page (`H_OFFPAGE`) values are read. anchore/go-rpmdb handles
only the second, and on every image measured the sole inline data item is the reserved key-0
counter — safe today, not guaranteed by the format, and a package small enough to fit on a page
would otherwise vanish silently.

**Big-endian databases are read too.** BerkeleyDB writes its integers in host order and s390x
is a supported RHEL platform, so the magic doubles as the byte-order probe rather than
little-endian being assumed.

**Still not read: ndb.** openSUSE and SLES only, and there is no SUSE advisory source for it to
serve. Those images exit 2 with the backend named.

---

### Replaying an rpmdb write-ahead log

**Why deferred.** A `rpmdb.sqlite-wal` larger than its 32-byte header currently fails the
scan (D45). Replaying it instead would be correct rather than merely safe: the log's frames
hold the newest version of each page, and reading them would give the same answer real SQLite
gives.

The refusal was chosen because the failure modes are asymmetric. A refusal is loud and exits
2; a replay with a subtle bug in its checksum or commit-frame handling is a package list that
is quietly wrong, which is the class D45 exists to close. All ten images measured carry a
zero-byte log, so the refusal has never fired on real input.

**Revisit when** it fires on a real image, or when scanning a live host rather than an image
becomes a target — a running system checkpoints on its own schedule and would meet this
routinely.

**Groundwork.** `ReadSQLite` already takes the log's size as a required argument, so the call
sites already reach the sibling file. What is missing is the 32-byte log header, the 24-byte
frame headers, the salt and checksum validation that says which frames are committed, and the
page overlay.

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

### ~~Publishing the database as an OCI artifact~~ — resolved in slice 8

`assay db update` pulls the published database from `ghcr.io/kun9497/assay-db`, tagged with
the schema version — `assay db ref` prints exactly the tag a given binary reads. `assay db
build` is the builder's command now: it still builds from the upstream providers, and a new
`--seed <ref>` lets a scheduled run layer onto the previously published artifact instead of
repeating the full pass. That is the only way the build fits inside GitHub Actions' six-hour
job cap against the seven-hour NVD sync this entry's own revisit trigger measured. `assay db
push <ref>` publishes. A scan still fetches nothing (D14). Full reasoning in D28.

The shape delivered is exactly what was scoped here: grype's and trivy's — a builder builds,
everyone else downloads — over `ghcr.io`, at no new dependency cost, since
`go-containerregistry` was already in the module graph for the registry `Source`.

The first artifact is not produced by the schedule; it is a one-time, manual bootstrap
(`NVD_ENABLE=1 assay db build` locally, then `assay db push`), because the daily workflow
seeds from an artifact that must already exist. See the README's "Bootstrapping the first
artifact".

---

### Checkpointing a long sync

`db build` assembles a temporary database and installs it only at the end, so a failure
anywhere discards everything the run had done.

**Why deferred.** It was invisible while OSV was the only source: an archive download is a few
minutes, and losing it costs a few minutes. NVD changed the arithmetic — the first real
bootstrap lost 42, 116 and 352 minutes to three separate failures before a bounded run
succeeded. Retries make a single page survivable and do not make a run resumable; those are
different problems, and only the first is solved.

Deferred rather than built because the bounded window makes it avoidable today. A 30-day pass
is 27 minutes, which is cheap enough to simply repeat, and the publishing artifact means most
people never build at all. Checkpointing also needs decisions this project has not had to make
yet — where a partial database lives, how a resumed run proves the checkpoint matches the
window it is resuming, and what happens when the schema changes underneath one.

**Revisit when.** A full unbounded pass becomes necessary — because the 30-day seed's coverage
is not enough, or because someone wants to rebuild from scratch without a published artifact to
start from. At seven hours with no resume point, that is not a job anyone can rely on
completing.

**Groundwork.** `Provenance.Window` already records what a run covered, which is the fact a
resumed run would have to match against. The temporary-then-rename install is the right shape
to build on: a checkpoint is a temporary database that outlives one process rather than a new
mechanism.

---

### Signing and provenance for the published database artifact

The artifact `assay db push` publishes, and `assay db update` / `assay db build --seed` pull,
is not signed and carries no build provenance (SLSA or otherwise).

**Why deferred.** A pull is already digest-verified by `go-containerregistry` — a corrupted or
tampered blob is rejected before it reaches disk — but that only proves the bytes match what
the manifest claims, not *who* built them. Left out of the publishing slice (D28) because it
is its own decision: which signing scheme (cosign/Sigstore keyless is the obvious fit for
`ghcr.io`), what verifies it (`Pull` would need to gain a verification step, not just a
fetch), and what a failed verification should do — the same "exit 2, never silently proceed"
question D14 and D16 already answer for other trust boundaries, not yet asked here.

**Revisit when** the artifact is consumed by anyone beyond its own builder's CI. Today the
same GitHub Actions identity builds and pushes, so there is no supply chain to attack yet;
that changes the moment a third party's `db update` trusts this registry by default.

**Groundwork.** `dbcmd.Push` and `dbcmd.Pull` already route every registry interaction
through `go-containerregistry`'s `remote` package, so a `cosign.Verify`-shaped step is
additive to `Pull` later, not a rewrite.

---

### Splitting KISA data into a separate artifact

**Why deferred.** No longer blocked on artifacts existing — they do now (D28) — and no
longer blocked on KISA enrichment itself, which now ships (D29, slice ⑤). What blocks it
today is that the data cannot be published in *any* artifact: KISA's terms restrict
redistribution, so `db push` strips the `enrichment` bucket before publishing rather than
choosing which artifact carries it. Splitting it out would solve a distribution-size problem
this decision does not have yet — the bucket is a `CVE → title/summary/URL` mapping fetched
in ~41 requests, nowhere near the size that would make bundling it a real cost.

**Revisit when.** Both halves of a concrete trigger fire together: the licence question D29
defers resolves — a 공공누리 mark appears, or KISA answers directly that redistribution is
permitted — **and**, separately, the enrichment data has by then grown large enough that
bundling it with the main artifact costs users who do not want it a download they cannot
skip. Until the licence resolves, this entry has nothing to fire on at all; the trigger is
that combination, not either half alone.

**Groundwork.** `Advisory.Source` makes partitioning by provider straightforward, and the
`enrichment` bucket is already its own bbolt bucket, keyed `(CVE, Source)` exactly like
ratings — splitting it into a second artifact later is a choice about what
`dbartifact.Pack` reads from, not a schema change.

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

`requirements.txt` stayed out at the time, and **D38 brought it in on 2026-08-06** without
reversing the reasoning: the lines that name exactly one version become packages, and every
other line is counted and named. Refusing the file to avoid guessing at some lines threw away
the ones that need no guessing.

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

### ~~Ingesting NVD as a rating source~~ — resolved in slice ⑦ (D27)

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

**Resolved 2026-08-04 as D27.** The shape the measurement pointed at is the one that
shipped: NVD joined on the CVE as a *rating* source, never as a matching source, reusing D25's
mechanism unchanged. The full-corpus run on 2026-08-05 rated **354,067** CVEs. The independent
CPE matcher this entry weighed against it stays unbuilt and stays contradicted by the same
evidence — see *Debian and Ubuntu package support* and *RHEL-family package support* for the
backport hazard that is the reason.

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
| OSV's RHEL-family coverage is thinner than Alpine/Debian | **Wrong as stated.** A `Red Hat` ecosystem exists (25 MB compressed). Whether it is backport-aware enough for accurate matching was still open here; resolved 2026-08-07 below — it is, and a different kind of thinness is the problem instead. |
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

### Resolved — measured 2026-08-07

| Assumption | Outcome |
|---|---|
| OSV's Red Hat data is backport-aware enough for accurate RHEL matching | **Confirmed, and it is not what blocks RHEL.** All 588,150 fixed events carry an epoch and a release, 95.8% carry `.elN`, and no upstream-shaped version appears anywhere. Checked against a real `ubi9` image, every patched package reads as fixed. What blocks matching instead is that the feed is *errata-only* — it cannot express "affected, will not fix", a class covering 39,372 CVEs that exist only in Red Hat's VEX feed. See *RHEL-family package support*. |
| Reading the rpmdb needs a third dependency | **Wrong.** A scanner only enumerates, never looks up by name, so the hash index is dead weight: a sequential page walk recovers every record, self-checked against BerkeleyDB's own key-0 counter (185 packages on `ubi8`, 107 on `amazonlinux:2`). The SQLite side is a b-tree scan with overflow chains, validated byte-identical against real SQLite on 7 images. `modernc.org/sqlite` costs 4 modules, 136 packages and 3.8 MB to buy the one backend that is cheapest to write (D44). |
| RHEL 8 uses ndb, so only EOL RHEL 7 needs BerkeleyDB | **Wrong.** Verified by magic bytes on `redhat/ubi8`, `almalinux:8` and `rockylinux:8`: all three ship the multi-file layout with `Packages` as a BerkeleyDB hash (`0x00061561`). ndb is openSUSE/SLES only and no Red Hat lineage uses it. Both engines are needed. |

### Still open

| Assumption | What depends on it |
|---|---|
| grype's default database-age behaviour is a warning, with enforcement opt-in | Only referenced as prior art, not depended on |
