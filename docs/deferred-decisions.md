# Deferred decisions

*English · [한국어](deferred-decisions.ko.md)*

Everything here was considered and postponed on purpose — none of it was overlooked.
Each entry records why it was deferred, what should trigger revisiting it, and any
groundwork already in place so that picking it up later stays cheap.

Read alongside the Architecture section of the [README](../README.md).

---

## Deferred work

### ~~The published database lost 352,000 NVD ratings and will not recover them on its own~~ — recovered in full, 2026-08-14 (D65, D66)

**Closed.** The artifact holds **357,678** ratings against `:v7`'s 355,030 — the recoverable
maximum, not a partial recovery: walking the remaining `lastModified` bands back to the
feed's edge fetched 17,476 more records and **not one carried a score** (NVD's unenriched
backlog and rejected records). The recovery took one accidental 51-minute whole-window run
(the D65/D48 cap composition — luck), then seven deliberate ratings-only slices (~2.5 min
each) proving the tail empty. Coverage claim: `modified 2023-08-30..now`, which the band
probes show IS the entire feed. The original entry follows, kept for the mechanism.

**When: soon.** This is not deferred because it is unclear — it is an open defect with a
known remedy, and the remedy is an operation rather than a code change, so it would leave no
trace anywhere else.

The published artifact at `:v8` carries **3,081** NVD ratings. `:v7` carried **355,030**.
Measured 2026-08-13 by pulling both and counting the ratings bucket.

**How it happened.** D52 bumped the schema, so the daily job had no `:v8` to seed from and I
bootstrapped one by hand from a local build with `NVD_ENABLE` unset. `refuseCoverageRegression`
compares against the artifact at the *same tag*, `:v8` did not exist yet, and every check was
skipped — at exactly the moment a hand-built artifact is most likely to be missing something.
D60 closes that hole for the next bump: the first push to a new schema tag now compares
against the previous schema's tag.

**Why it does not heal on its own.** The daily job fetches an *incremental* NVD window. The
API caps any range at 120 days and the 2026-08-12 run covered about 30, so a rating for a CVE
last modified in 2023 is never re-requested. The count climbs by one day's modifications a
day; the 352,000 stay gone.

**Why it matters more than a missing field.** A finding whose rating is gone reports `unknown`
severity, and D17 deliberately keeps `unknown` outside the `low < medium < high < critical`
ordering — so it does not trip `--fail-on critical`. A finding that would have failed a build
now passes it, and the report is honest the whole time: it says the finding is unrated, which
is true. Nothing anywhere says it used to be rated critical. This is the silent-miss direction
the whole project is built to avoid, arriving through the database rather than the matcher.

**The remedy.** ~~One unbounded NVD sync~~ — measured, and rejected the way the README's
bootstrap section already had: seven hours, no resume point, four failed attempts on record.
D65 replaces it with bounded slices walked backwards (`NVD_UNTIL_DAYS` closes the window's
late end; the published artifact is the checkpoint between slices; coverage only extends when
a slice touches the range already covered). The README's "Backfilling older ratings" section
is the runbook. Then confirm the ratings count against `:v7`'s 355,030.

**It blocks the entry below.** *Does an unrated source count as disagreeing?* asks for a
measurement against a full NVD-enabled database. Today's run — ubi9, 9 of 783 findings marked,
none marked solely because an unrated source counted as disagreeing — was taken against these
3,081 ratings. That number says NVD is nearly absent, not that the marker is quiet.

### Reading pnpm lockfiles — a YAML parser as a third dependency

`pnpm-lock.yaml` is recognized, named, and exits 2 (D61). Reading it is deferred on one
question: whether this project takes a third direct dependency.

**This entry said "and uv" when it was written, and that was wrong.** See the entry below —
`uv.lock` needs no library, and lumping the two together made a measurement sound like a
constraint.

**Why deferred.** Neither YAML nor TOML is in the standard library, and the two direct
dependencies this repo has are deliberate (`bbolt` for the store, `go-containerregistry` for
registry, tarball and OCI-layout reading). pnpm's format is real YAML — anchors, nested
importers, the `snapshots` section — so hand-parsing it is the kind of "restricted subset"
that works on fixtures and quietly mis-reads a real file. A parser that silently gets a
version wrong is worse than one that refuses.

**Left refusing rather than guessing** because the refusal is loud and correct: exit 2 says
this scan looked at none of the tree, which is exactly what happened. The cost is that a pnpm
or uv repository cannot be scanned at all, not that it is scanned wrongly.

**Revisit when** either a pnpm/uv repository is something this tool is actually pointed at, or
a third dependency is being taken for another reason and the marginal cost drops to zero.
`gopkg.in/yaml.v3` and `github.com/BurntSushi/toml` are both pure Go, so the `CGO_ENABLED=0`
constraint does not decide this — only the dependency count does.

**Groundwork.** The Kinds, the walk entries, and the dispatch arm all exist; reading them is a
parser and one `case` each. `markupOf` in `dirscan.go` already names which reader each format
needs.

**Yarn berry rides on the same decision.** Berry is YAML under the `yarn.lock` filename, and
`yarnlock.isBerry` detects and refuses it today. The same YAML parser would cover it.

### ~~`uv.lock` — measured readable, cataloger not written~~ — resolved the same day (D63)

Read as of D63. Kept here because the entry above it was written wrong, and the record of how
is worth more than the entry was.

**Measured 2026-08-13**, against `astral-sh/uv`'s own 1,650-line `uv.lock`: the line scanner
written for `Cargo.lock` parses **77 of 77 `[[package]]` blocks with none skipped**. The file
is the same flat shape as `poetry.lock` and `Cargo.lock` — name and version are bare quoted
scalars at the top of each block — and the first-assignment-wins rule steps over the inline
tables inside `dependencies` without special handling.

**What it took.** A `uvlock` package shaped like `cargolock`, a Kind, and a dispatch arm — the
scanner moved to `internal/cataloger/tomlblock` so the two cannot drift. Scanning uv's own
repository finds 23 findings across all 77 packages, none not-evaluated. PyPI was already
ingested, so no database rebuild was needed.

**The lesson, which is why this entry stays.** D61 asserted this file needed a TOML reader,
reasoning from the format's *name* rather than from the file. A deferred entry that names a
wrong constraint is worse than one that names none: "needs a third dependency" reads as settled
and stops anyone looking, where "nobody has written it" invites the twenty minutes it actually
took. Before deferring on a constraint, measure the constraint.

### Ecosystem coverage against grype — the gap, remeasured

grype ships **26 providers**; assay had **4** when this entry was written (2026-08-13) and
has **8** since the RPM-family series closed (OSV, Red Hat CSAF, Amazon ALAS, Oracle ELSA
OVAL, Fedora Bodhi, SUSE CSAF, NVD ratings, KISA enrichment). grype's list for reference:
alma, alpine, amazon, arch, bitnami, chainguard, chainguard-libraries, debian, echo, eol,
epss, fedora, github, govulndb, hummingbird, kev, mariner, minimos, nvd, oracle, photon,
rhel, secureos, sles, ubuntu, wolfi.

**Why this entry stays.** The differential runs in this repo were all taken on ecosystems
assay covers — a selected sample. The 2026-08-13 version of this entry said assay found
nothing on Amazon Linux, Oracle, SLES, or a Java/Ruby/Rust/.NET/PHP application; D68–D79
closed every one of those (language ecosystems D68–D70, the RPM family D71–D79). What is
STILL true: on Photon, Wolfi, Chainguard, Mariner/Azure Linux, Arch, or the other boutique
apk-family distros, **assay finds nothing at all** — those images are catalogued and
reported as not evaluated, a loud refusal, not support. grype also ships enrichment feeds
assay has no equivalent for: EPSS scores, KEV (known-exploited), and EOL data.

**What each would take.** The remaining distros are each their own advisory feed in their
own format (Wolfi/Chainguard publish OSV-shaped advisories — likely the cheap ones; Photon
and Mariner publish their own JSON/OVAL). EPSS/KEV are rating-shaped joins on CVE, the same
mechanical shape as the NVD join (D27) — cheap to ingest, but each is a new decision about
what the gate does with it.

**Revisit when** a specific ecosystem has a reason to exist rather than as a coverage count.
A comparer with no provider behind it is the shape D46 refused for RPM, and a provider with
no measured demand is corpus size paid for nothing — the Ubuntu archive alone added 6 GB and
36 minutes of build (D53, D56).

---

### Ubuntu findings carry no fix state

D52 distinguishes "the vendor will never fix this" from "no fix yet" and D53 brought Ubuntu
in, but every Ubuntu finding reports `unknown`. On a real ubuntu:22.04 scan that is all 104 of
them, while grype marks **15 as wont-fix** on the same image.

**Why.** Not a bug in the matcher. OSV's Ubuntu export carries no fix-state field at all;
grype gets it from Canonical's Launchpad CVE tracker through vunnel, where the state is a
per-package pocket annotation rather than anything OSV represents. D17's discipline is why
the finding says `unknown` rather than guessing, and that is the right answer for the data —
but the information exists and assay is not reading it.

**What it would take is a D1 question, not an implementation one.** D1 says every provider
normalizes into OSV shape, and that is what made the KISA and Red Hat providers possible.
Reading Launchpad means a second Ubuntu source whose native shape is not OSV's, alongside an
OSV Ubuntu ingest that already works — either two providers for one distro, or replacing the
OSV path with a Launchpad one and inheriting a scraper nobody else in this project maintains.

**Revisit when** the wont-fix distinction matters on Ubuntu the way it did on RHEL. The
measured share is what to check first: 15 of 104 findings on ubi-equivalent Ubuntu against
59 of 505 on ubi8 — similar enough that the case is probably as strong, and worth measuring
properly before reopening D1.

---

### ~~A whole-project QA pass before anything is called finished~~ — first pass run 2026-08-19

**Run when the architecture table filled in** (D70 made every cell bold), as five parallel
auditors over the four defect classes this entry names, each finding carrying the exact
one-line mutation that would prove it, verified in isolated worktrees against the FULL suite
— the cross-slice requirement, mechanized.

**Results: 25 findings, 9 verified by mutation, every verified one real (0 false alarms).**
The confirmed gaps, all closed the same day by tests that turn those exact mutations red:
`Unread.Failed` unheld on the jar arm (a corrupt .jar exited 0 under `--fail-on-incomplete`);
the OSV zero-record guard held for Alpine only; NVD's emit error swallowed (a store-write
failure during `db update` reported success); the four D68 comparers' REGISTRY wiring
untested (the seventh instance of helper-covered-nothing-calls-it — `"RubyGems": SemVer{}`
survived); `--db-max-age` parsed and dropped; knvd's URL tie-break; D3's `upstream`
identifiers and D41's source-version comparison unheld on the consumer side; one substring
assertion in the test written for the substring-assertion class.

**Still open: 14 unverified medium/low findings** (SARIF renderer arm, the D11 interaction
matrices, PullSeed contract arms, OpenSeedRatings pin, reportTimings wiring, others) — the
next pass's starting list, recorded in the QA workflow journal. The original entry follows.

**Why this is written down rather than assumed.** Every slice in this project has shipped
with its own tests and its own mutation round, and mutation testing still found real defects
in four of them — including two where the helper was covered and the wiring that calls it was
not, which no per-slice review caught because each slice's tests looked complete on their own.

**What it should cover, based on what has actually broken here:**

- **Wiring, not helpers.** The recurring defect: a function tested in isolation and nothing
  asserting anyone calls it. Four instances so far (the failure-path timing report, the
  store-split value reaching the table, the SARIF not-evaluated rule declaration, the
  `Ecosystems` entry).
- **Substring assertions.** Documented twice in CLAUDE.md and hit twice more since, once in
  the test written to catch that very class.
- **Cross-slice interaction.** Every mutation round so far has been scoped to one package.
  Nothing has tried mutating one slice's code and running another's tests.
- **The exit-code contract end to end.** D11 fixes 2 > 1 > 0, and each gate was tested
  against its own flag rather than against the others.

**Revisit when** the feature set stops moving. Doing it mid-slice would measure a shape that
is about to change, and the value is in the sweep being whole.

---

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

### ~~Ubuntu package support~~ — resolved in slice ⓲ (D53)

**Why deferred.** Not the version scheme — the dpkg comparer D40 added handles Ubuntu
revisions (`2.4.4-2ubuntu17.10`) unchanged. Two other things.

OSV keys Ubuntu as `Ubuntu:24.04:LTS`, and its Pro and FIPS lineages —
`Ubuntu:Pro:FIPS-updates:18.04:LTS`, `Ubuntu:Pro:20.04:LTS` — describe the **same release**. A
release-only ecosystem key cannot separate them, so a scan of an ESM-patched system would
match the non-ESM lineage's fixed versions and report it vulnerable. That is a systematic
false positive, and D6's "the release is in the key" is not enough on its own; the key has to
carry the lineage too, which is a decision about what an ecosystem key means rather than a
line in the distro mapping.

The corpus is also 6.03 GB unpacked against Debian's 254 MB, so the provider would have to
stream rather than parse records whole.

Both of those numbers were wrong when this was written, and the correction changes what the
work is. Debian's was quoted as 383 MB — an on-disk figure inflated by 4 KB allocation
blocks against a 4 KB mean record, not the 254 MB the content actually weighs. And the cost
is not `versions[]`: those are 23.2% of Ubuntu's bytes against 49.5% of Debian's, so Ubuntu's
are proportionally SMALLER. What multiplies is affected entries per record, 38.9 against 3.4,
because each record lists one per (lineage × release × binary package). Dropping the lineage
entries is therefore both the correctness decision and the size one — see D53.

**Resolved 2026-08-10**, by taking the measurement this entry asked for — which reversed the
direction it predicted.

The entry expected a false positive. Of the (CVE, package) pairs at one release carrying both
a mainline and a lineage fixed version, **67 of 67 differ and 67 of 67 have the lineage version
sorting strictly higher**: Canonical appends `+FipsN` to the identical base version and dpkg
orders a `+`-suffixed string above the string it extends. So mainline is always the lower bar
and the error is a **silent false negative** on a FIPS host, not a false alarm — 72 of 136
triples on a real 22.04 image and 14 of 23 on 24.04, every one in that direction and none in
the other. The false-positive case the entry describes could not be tested at all: 22.04 has
not left standard support, so no ESM-infra record exists yet to check against.

D53 keys mainline only and reports a lineage-built package as not evaluated, detected from its
own version suffix — the one signal that survives, because Canonical's documented way to build
a FIPS or ESM image deletes every config file an attachment writes while leaving the patched
binaries in place. See D53 for why that makes Ubuntu's detectability worse than RHEL's rather
than better, and for how the 6.03 GB corpus is cut down at ingestion.

**Two gaps remain open and are recorded rather than closed:**

- **Realtime and Nvidia-BlueField.** Those lineages differ by package NAME
  (`linux-realtime`, `linux-bluefield`), not by a version suffix, so D53's detector cannot see
  them. A container image ships no kernel, so this is a host-scan gap. Revisit if assay ever
  scans a live host's `/proc`, or if a name-based rule earns a measurement.
- **No lineage image was ever tested.** Every number above compares a confirmed-mainline
  image's versions against lineage thresholds, because no Pro/FIPS image is anonymously
  pullable — they ship only behind a paid marketplace subscription. The detector rests on
  Canonical's advisory data and syft's regex, never on an observed installed package. Revisit
  if such an image becomes reachable.

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

**~~AlmaLinux and Rocky Linux are not the easier path~~ — the whole RPM family is resolved:
Rocky in D71, AlmaLinux in D72, Amazon Linux 2/2023 in D73, Oracle Linux 5–10 in D74, Fedora
in D75, and SLES plus openSUSE Leap in D77 (over D76's ndb backend). Tumbleweed is refused by
name — rolling, no release axis to key on.** Both keyed on the major version only — three
keys each, derivable from `/etc/os-release` — which is genuinely simpler. Neither Alma nor
Rocky survived the rest, at the time:

- ~~**AlmaLinux carries zero `aliases` and zero `upstream` fields** across all 5,494 records.
  Every CVE reference is in `related`, which OSV defines as explicitly *not* an alias. Under D3
  as written, AlmaLinux yields **0 CVEs** and the D25 rating join produces 0 matches. It also
  has no severity data at all (0% CVSS coverage, against Red Hat's ~84%), so under D17 every
  Alma finding would land in `unknown` and never trip `--fail-on`. Reading `related` is a
  semantic change to the join, and therefore its own decision.~~ **Resolved in D72**, on top of
  the two decisions D71's research banked for exactly this: `related` joins the CVE read,
  scoped to distro-authored records (5,606 records measured 2026-08-19, CVE reachable through
  `related` on every one), and a summary's leading severity word ("Important: openssh security
  update") is stored losslessly as a `VENDOR_WORD` severity entry and banded by
  `internal/severity` — Critical/Important/Moderate/Low, the RHSA convention Alma's own ALSA
  summaries inherit byte-for-byte. Both were implemented WITH Alma, not before it; Alma is the
  record that could not ship without either.
- ~~**Rocky Linux's export is too incomplete to ship.**~~ Median 0.29 coverage of Red Hat's
  runtime package set, 83% of shared (CVE, major) groups missing at least one runtime package,
  only `curl` named for CVE-2023-38545 where Red Hat and Alma both name `curl`, `curl-minimal`,
  `libcurl` and `libcurl-minimal` — and **no record whatsoever for CVE-2024-6387**. **Shipped
  anyway in D71**: the same gap is still there, disclosed rather than closed — a `rockylinux:`
  target now exits 0 on a verdict documented as clean-of-what-Rocky-published, not clean.
- Alma also writes module builds as `module_el8.5.0+119+9a9ec082` where Red Hat and Rocky write
  `module+el8.5.0+12582+56d94c81`. That no longer matters for matching AlmaLinux itself — D72
  routes `almalinux` to Alma's OWN archive (`AlmaLinux:N`), not Red Hat's or Rocky's, so nothing
  compares Alma versions against another distro's advisory versions — but it is still why
  routing stays on `/etc/os-release` `ID` (`rhel` / `almalinux` / `rocky`) rather than on the
  shared `elN` release string, and why D71's module-build match-time guard (RPM-comparer-gated,
  not ecosystem-gated) had to recognize both spellings from the start: AlmaLinux's own feed
  carries `module_el` builds exactly as Rocky's carries `module+el` ones.

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

**Still deferred.** Only OVAL v2 as a second opinion (it covers RHEL 5–9 and has no RHEL 10,
so it could never be the primary source), and closing the EUS/AUS/E4S divergence rather than
disclosing it, which needs a channel signal no image carries. Every distro this entry
originally named is off this list — see D71 through D77 — and openSUSE Tumbleweed was never
on it: rolling releases have no release axis to key on, so it is refused by name rather than
deferred.

**~~Oracle Linux itself still owes one decision~~ — the lineage half is resolved in D79.**
Ksplice- and FIPS-lineage fixed EVRs are dropped at ingestion (12,174 measured, counted in
the stats line) and an installed lineage package is reported not evaluated by the matcher,
Ubuntu-D53's shape with Oracle's own two markers (`.ksplice<N>.` in the release, `_fips`
ending it — both measured across the full corpus, and the marker copies in the provider
and the matcher carry cross-referencing comments because they must not drift).

What remains is the train question, now a third smaller and better characterized. D74's
first ingestion dropped 43,123 affected entries (169,585 ambiguous (CVE, major, package)
groups); D79's lineage filter recovered 10,502 of them — 24.4%, openssl's entire ambiguity
among it, because a lineage EVR colliding with the mainline fix made D74's guard throw both
out. Post-D79 the guard drops 32,621 entries across 158,119 groups, and the composition was
measured (2026-08-20): kernel* packages are 83.4% of the GROUPS but only 40.7% of the
ENTRIES; perf/bpftool/python-perf (~790 entries) are kernel-train artifacts by another
name; and the biggest non-kernel names — nodejs (106), postgresql (87), qemu (90) — are not
a UEK problem at all but MODULE STREAMS re-fixing the same CVE per stream, i.e. the
MODULARITYLABEL deferral D71 decision 3 already records. The genuinely open question is
narrower than it looked: train-aware matching (or keeping the earliest fix) for the
kernel-and-kin remainder, which only pays off on host/rootfs scans — container images ship
no kernel. Conservative direction meanwhile (no wrong-train match), unchanged.

**Revisit trigger:** a host/rootfs scan user appears — the kernel-train remainder is the
only part left. The module-stream slice of the remainder went to MODULARITYLABEL matching
when it started (D80; Oracle's stream attachment lands in D81), which is the second trigger
firing.

**The five decisions this research forced now live in D71**, not here, because the next
distro slices reuse them: reading `related` for CVE joins, scoped to distro-authored records;
storing a losslessly-kept vendor severity word alongside an NVD join; dropping and counting
module builds instead of stream-matching them; treating OSV as the primary feed where it
exists; and SLES staying behind `ndb`. D72 (AlmaLinux) is the first slice to actually spend
the first two of those five — see D72 in the roadmap.

**The `ndb` half of that list was resolved first — D76 reads the format.** Modern SLES/BCI
images could not be catalogued at all, measured independently of any advisory question; that
justification for deferring `ndb` no longer held once measured, so the backend was built and
verified against a real `registry.suse.com/bci/bci-base` image (138 packages, 0 skipped — see
the roadmap's D76 entry for the full verification). D76 was cataloging only, on purpose; the
advisory half — SUSE's own CSAF VEX feed, and the `sles`/`opensuse-*` ecosystem keys and
comparer routing it needs — is resolved in D77, closing the RPM family entirely.

---

### ~~Whether the published artifact carries the Red Hat data~~ — resolved in slice ⓰ (D51)

**It does.** `db push` publishes whatever the database holds, and there was nothing to add:
the feed is TLP:WHITE on all 67,261 documents, so unlike KISA (D29) there is no strip step.

Measured 2026-08-07 on the same machine, with the concurrent delta in place:

| | without Red Hat | with |
|---|---|---|
| artifact download | 20.9 MB | **28.7 MB** |
| database on disk | 512 MiB | 1.07 GB |
| `db build` wall clock | ~10 min | ~28 min |

The download is what a user feels, and 8 MB more for the only source that can say a package is
affected and will not be fixed decided it. `REDHAT_ENABLE` now defaults ON to match, because a
default disagreeing with the artifact would make `db build` and `db update` produce different
databases and `db push` refuse the narrower one. See D51.

---

### ~~The VEX archive lags its own change feed~~ — resolved in slice ⓯

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

**Resolved 2026-08-07.** `changes.csv` is read after the archive and every document newer than
the archive's own date is fetched individually. Only a 404 is survivable — a document withdrawn
between `changes.csv` and `deletions.csv` being written is a race, and everything else fails
the build rather than closing part of the gap and looking complete.

**What is NOT handled, and the measurement that says why.** A document present in the archive
and DELETED afterwards still gets ingested: deleted paths are removed from `changes.csv`, so
only `deletions.csv` names them, and that file is 15 MB and 280,953 rows. Measured against the
2026-08-05 archive there was **exactly one** such deletion, and about 30 a month. The exposure
also closes on its own — the next archive rebuild drops the document — so the window is one
archive cycle for roughly one record. Revisit if that ratio changes, or if the store ever gains
a reason to download `deletions.csv` anyway.

Note the interaction with *Checkpointing a long sync*: the delta pass is the part that would
want resuming, not the archive read.

---

### ~~Red Hat's fix state is collapsed to "there is no fix"~~ — resolved in slice ⓱ (D52)

**Why deferred.** CSAF distinguishes remediation categories that this provider does not keep.
Archive-wide there are 22,289 `no_fix_planned` and 16,935 `none_available` remediations, and
grype surfaces the same distinction as `wont-fix` versus `not-fixed`. On the ubi9 differential
grype's 415 shared findings split **404 `not-fixed` / 11 `wont-fix`**; assay reports all 415 as
"no fix available".

The two mean different things to a reader. "Red Hat has decided not to fix this" is final and
the only remaining moves are mitigation or removal; "no fix yet" is a reason to watch the CVE.
Collapsing them loses an action, not just a label.

**Why it was deferred.** D48 chose the OSV range shape — an `introduced` event and no `fixed`
one — precisely because it needed no schema change, and that shape had nowhere to put a
reason. Carrying it meant a store change that D5 turns into a schema bump and a rebuild, and the
revisit trigger was "when the store next changes shape for another reason".

**Resolved 2026-08-10**, and not by that trigger — nothing else wanted a schema change. It was
done on its own merits once the cost of leaving it was measured against the cost of moving: a
rebuild for everyone, against a distinction that turns out to apply to **every** unfixable Red
Hat finding rather than to a fraction of them.

The number that decided it was coverage, not the split. Of the 1,282,093 mainline
(CVE, ecosystem, package) tuples with no fixed version in the 2026-08-09 archive, every single
one is named by a `no_fix_planned` or `none_available` remediation — zero carry neither. Had a
large fraction been uncategorised, most findings would have stayed "no fix available" whatever
the schema did, and the rebuild would have bought a label for a minority.
`stats.UnfixableUnstated` counts that bucket on every sync, so the day it stops being zero is
visible rather than inferred.

The field went on `advisory.Range` rather than on the advisory, because a package can be fixed
on one release and permanently affected on another and both ranges are emitted side by side.
The gate is a scope on the existing flag — `--fail-on-unfixable=wont-fix`, following D36's
`--fail-on-incomplete=target` — so no existing CI changed behaviour. See D52 for the tie-break
on the 179 packages Red Hat tags both ways, and for why `fixed` is derived rather than stored.

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

**ndb, the third format (openSUSE and SLES only), is read too — as of D76.** It was left
unread here for the same reason ndb stayed off D44's list: no SUSE advisory source existed for
it to serve. That justification stopped covering the cataloging half once measured — modern
SLES/BCI images could not even be catalogued, independent of any advisory question — so D76
built the backend; those images now scan to completion and are reported not evaluated, the
same way every other unrouted RPM family already is, rather than exiting 2 before the package
database can even be opened. There is still no SUSE advisory source; that half is unchanged.

---

### Detecting a RHEL EUS/AUS/E4S host from its package versions — **measured and rejected**

**The idea.** D53 closed Ubuntu's lineage problem by detecting the package BUILD rather than the
entitlement: an installed `+esmN` or `+FipsN` version is baked into the package database and
nothing can purge it. RHEL looks like it offers the same handle — EUS builds carry a
minor-qualified release string (`.el8_6`) where a mainline build carries a bare one (`.el8`) —
which would close D47's known hole: an EUS host is currently quoted mainline fixed versions.

**It does not work, and the reason is that the suffix means something else.** Measured over the
2026-08-09 CSAF archive with the provider's own parsing rules, `.elN_M` marks a z-stream rebuild
against a released minor — something mainline does constantly:

| channel | bare `.elN` | minor `.elN_M` |
|---|---:|---:|
| mainline (4,519,290 entries) | 31.3% | **61.7%** |
| EUS family (1,468,830) | **10.0%** | 89.9% |

The mainline share rises with the major: **92.6% on RHEL 9 and 97.8% on RHEL 10.** A detector
keyed on the suffix would refuse to evaluate nearly every current RHEL 9 and 10 package — and a
stock UBI image, which is indisputably mainline, already carries it on 24–30% of its RPMs
(55 of 185 on ubi8:8.9, 44 of 183 on ubi9:9.3).

And it would still miss what it exists to catch: **10.0% of genuinely entitled EUS-family builds
carry a bare suffix**, in every channel measured and not only in old data — CVE-2025-53057 ships
`java-1.8.0-openjdk-1:1.8.0.472.b08-1.el8` on `rhel_eus_long_life:8.4`.

So it fails in both directions at once. That is the mirror image of D53's Ubuntu result, where
the marker collided with mainline zero times in 67 of 67 measured groups. The techniques are not
transferable, and the reason is worth keeping: Ubuntu's marker names a PRODUCT LINE, RHEL's
names a REBUILD OCCASION that every product line shares.

**What the hole actually costs, now that it is measured.** Of 155,549 (CVE, package, major)
groups where mainline and a channel give different fixed versions, mainline sorts HIGHER in
**149,726 (96.3%)**. So today's mainline-only matching mostly over-alarms an EUS host — it
demands a version that channel never needed to reach — which is the loud direction this project
prefers, and D47's stderr note is the right handling for it.

**The 1.3% is the part that is not settled.** In 2,001 groups the channel's fixed version sorts
higher, so mainline's lower threshold reads such a host clean while its own channel has not
shipped the fix — a silent miss, the failure class this project ranks worst. It is concentrated
on RHEL 7 (392 of 7,658 directional groups, 5.1%) and thins out on 9 (0.8%). Nothing here closes
it: a suffix cannot, and no other filesystem signal is known.

**Revisit when** a channel signal exists that is not the release string — a subscription-manager
artifact in the image, an `/etc/yum.repos.d` entry naming an EUS repo, or a Red Hat feed that
states the channel per installed package. Ingesting the EUS CPEs as their own ecosystem keys is
NOT a route on its own: without a way to tell which channel a host is on, it would add keys
nothing can ever look up. Do not re-derive the suffix idea; it is measured and dead.

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

### ~~Does an unrated source count as disagreeing?~~ — measured 2026-08-14: yes, and it barely matters

**Closed, no change.** Measured against the complete NVD database (357,678 ratings), three
targets:

| target | multi-source | marked now | marked if unrated excluded | delta |
|---|---:|---:|---:|---:|
| ubi9 | 415 | 140 (33.7%) | 139 | **1** |
| ubuntu:22.04 | 85 | 1 | 0 | **1** |
| python:3.9-slim | 271 | 11 | 11 | **0** |

The predicted flood never arrived: excluding unrated sources would change at most ONE finding
per scan, because NVD now rates nearly everything a second source also describes — the
disagreements are between two RATED sources. Changing the report's contract for a delta of one
is not worth the divergence.

ubi9 does cross the entry's own ~30% "marker stopped working" threshold — at 33.7% — but for
the opposite reason the entry predicted: NVD and Red Hat genuinely land on different bands for
a third of shared findings (111 adjacent, 28 two-plus bands apart). Red Hat rates within its
product context, NVD in the abstract. That is signal, not noise: the gate takes the highest
band (D25), so a reader deserves to know when the sources it aggregates disagree. The marker
is doing its job; the original question follows, kept for the reasoning.

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

**Attempted 2026-08-13, and it did not answer.** ubi9 marked 9 of 783 findings, and not one
of them was marked *solely* because an unrated source counted — which reads like the marker is
healthy and is not evidence of anything. The database used carried 3,081 NVD ratings instead
of 355,030 (see the first entry above), so it was not the full NVD-enabled database this
condition asks for; it was very nearly the pre-D27 database. Redo the measurement after the
ratings corpus is restored, and do not treat the 9-of-783 as a baseline.

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

### CycloneDX maps no `rpm` purl type

Found by D78's E2E, not by a reader: `purlTypeToEcosystem` has no `rpm` entry, so an SBOM
naming an RPM-family package (`pkg:rpm/amzn/containerd@...`) never reaches the matcher —
the whole distro side of the database is unreachable from the SBOM path. It is not a
one-line fix, which is why it is here: an `rpm` purl carries its distro in a qualifier
(`distro=amzn-2`, `distro=rhel-9.4`), not the type, and mapping that to release-qualified
ecosystem keys (D6) needs the same os-release normalization the image path gets from
`internal/pkgmeta` — plus a decision about purls with no distro qualifier at all (report
as not evaluated, presumably, D17's register). Until then RPM-family scanning is image-
and directory-only; D78 verified its extras findings at the matcher seam instead.

**Revisit trigger:** the first user scanning distro SBOMs (syft emits exactly these purls),
or SPDX ingestion above landing first — the mapping should be built once, shared by both
parsers.

---

### AL2023's NVIDIA and livepatch repos

D78 closed AL2's extras gap; AL2023's equivalent stays open and disclosed. 306
ALAS2023NVIDIA + 286 ALAS2023LIVEPATCH advisories (measured 2026-08-19 from the ALAS RSS)
live outside AL2023 core, and the AL2 approach does not transfer: AL2023 publishes no
extras catalog at the parallel URL (403, verified 2026-08-20) — its extra repos are DNF
modules with a different layout that was not researched in D78's slice. The Fetch
disclosure line names this remainder, so a core-plus-AL2-extras build cannot read as
covering AL2023 completely.

**Revisit trigger:** someone scans an AL2023 image with NVIDIA drivers or livepatches
installed, or the AL2023 repo layout gets measured the way `amazon-research.json` measured
AL2's.

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

### ~~SARIF output~~ — resolved in slice ⓴ (D55)

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


**Resolved 2026-08-11.** The mapping was never the hard part; the question the entry named —
what a location means, and what happens to a package with no finding — turned out to have a
sharper form. GitHub code scanning does not support `invocations[]`, so the spec's own channel
for "what this run could not do" is invisible in the consumer that matters. D55 emits skips
there AND as note-level results, so a partial scan cannot read as a complete one. See D55 for
why an unrated finding gets no `security-severity` and why fingerprints ignore the version.

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
