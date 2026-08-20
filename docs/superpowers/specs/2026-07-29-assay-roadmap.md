# assay — architecture and roadmap

*English · [한국어](2026-07-29-assay-roadmap.ko.md)*

**Date:** 2026-07-29
**Status:** Agreed. Supersedes the scaffold's original framing.

This is the reference design for the whole project. Individual slices get their own
implementation plans; this document records what the system is, why it is shaped this way,
and the order it gets built in.

Deferred work, known hazards, and unverified assumptions live in
[`../../deferred-decisions.md`](../../deferred-decisions.md).

---

## 1. Goal

A single tool that takes a container image, binary, directory, or SBOM and reports the
known vulnerabilities affecting it — covering inventory generation, vulnerability database
construction, and matching.

In the anchore ecosystem those are three separate projects: `syft` builds the inventory,
`vunnel` + `grype-db` build the database, and `grype` matches. assay does all three.

**This is a personal project, built to learn how a vulnerability scanner works by building
one end to end.** Existing scanners are excellent and battle-tested; use them in production.
Nothing here is trying to replace them.

It began with KISA/KNVD as a first-class provider. The first investigation (2026-08-02)
concluded that was not viable, and **that conclusion was wrong because it measured the wrong
board** — KNVD's own disclosures (173 records, Korean domestic software) rather than its
security notices (2,422 records, CVE-keyed, about Apache, OpenSSL and the like). Corrected in
slice 5: KISA is not an independent matching source, but a CVE-keyed enrichment join does
fire, and three of three sampled notices are advisories assay already carries for Alpine
`apache2` and `openssl`.

What the build has actually produced, and what the design goals below are for, is a scanner
that does not give a confident wrong answer: it says why every finding matched, it says what
it could not evaluate, and it never fetches vulnerability data during a scan.

Design goals, in priority order: **explainable**, **offline-capable**, **boring output**
(deterministic, diffable, CI-friendly).

### Non-goals

Configuration scanning, secret scanning, IaC, and Kubernetes posture — the directions
trivy expanded into. They share almost no code with vulnerability matching; including them
would mean shipping a different tool inside the same binary.

---

## 2. Decisions

Each decision records the reasoning, because the reasoning is what makes it revisable.

### D1 — OSV is the normalization target

Advisories are stored in OSV shape: `affected[].ranges[]` carrying `introduced` / `fixed`
events.

The alternative was collecting upstream feeds directly (NVD CPE match ranges, OVAL
condition trees, distro secdb formats) and normalizing them ourselves. Each source
expresses ranges differently, and the normalization layer ends up larger than the scanner —
which is why anchore splits `vunnel` and `grype-db` into their own repositories.

Reusing a proven normalization target beats inventing one. OSV also has strong language
ecosystem coverage, which is where the first slice lives.

Reading grype's prebuilt database instead was rejected: its schema is anchore's internal
contract and changes across major versions, and — decisively — **a schema we do not own
cannot accept our own sources.** KISA rules it out.

### D2 — Provider abstraction from day one

Because KNVD data will not arrive in OSV format, some collection and normalization is
unavoidable. A `Provider` interface makes OSV a near-passthrough implementation and KISA a
second one, without committing to hand-rolling every upstream feed.

### D3 — KISA is enrichment first, not a matching source

A finding matched through OSV picks up its Korean description, KISA severity, and KNVD link
by joining on CVE ID. KVE entries do not produce findings of their own.

**The join must read both `aliases` and `upstream`.** OSV schema 1.7 records carry the CVE
link in `upstream`, not `aliases` — a sampled Alpine record has
`"upstream":["CVE-2006-20001"]` and no `aliases` at all. Reading only one field makes the
join fail silently, which is the worst kind of failure for enrichment: findings simply
appear without Korean data and nothing reports an error.

Many KNVD advisories describe domestic commercial software in prose with no ecosystem, no
purl, and no package name — CPE-style *product* matching rather than package matching. It
is also a poor fit for the current targets: container images and source trees do not
contain 한컴오피스. Deferred, with the promotion path recorded.

### D4 — bbolt for local storage

The access pattern is a point lookup by `(ecosystem, name)`, repeated once per package.
No range scans, no joins, no aggregation. That is pure key-value; SQL buys nothing.

`CGO_ENABLED=0` in the Makefile rules out `mattn/go-sqlite3`. The remaining SQLite option,
`modernc.org/sqlite`, is a machine translation of C into Go — a very large dependency for a
`go.mod` that currently has no `require` block at all.

SQLite's one real advantage is debuggability (`sqlite3 db "select ..."` during development).
That is recoverable through `assay db inspect`, which overlaps with the planned explain
mode anyway. trivy made the same call for the same access pattern.

`Store` is a small interface, so this is reversible if the reasoning turns out wrong.

### D5 — Schema version in the path

`<cache>/assay/db/v9/vulnerability.db`. A schema change means rebuilding into a new
directory rather than writing migration code. Migration code is a liability for a project
with one user.

### D6 — Distro packages key on their release

Ecosystem keys are `Alpine:v3.19`, not `Alpine`. The fixed version of a package differs per
release, so the release is part of the lookup key. This matches how OSV partitions distro
data.

### D7 — The distro belongs to the target, not the package

An *image* is Alpine 3.19; its packages are not. `Target.Distro` is read from
`/etc/os-release` once and applies to every OS package inside.

### D8 — `Package.Source` carries the source package

Distro advisories are written against **source** packages, while what is installed are
**binary** packages:

```
advisory:  source package  openssl     < 1.1.1n-0+deb11u3   vulnerable
installed: binary package  libssl1.1     1.1.1n-0+deb11u1
```

Looking up `libssl1.1` finds nothing. Matching requires knowing its source is `openssl`.
Without this the failure is a **false negative**, not a false positive — silent and far more
dangerous. Borrowed from grype's dpkg matcher.

**This applies to Alpine, not only Debian and RHEL.** A sampled OSV record carries
`"purl":"pkg:apk/alpine/apache2?arch=source"` — Alpine advisories are source-keyed too.
Since Alpine is the first distro (slice 2), indirect matching is needed there rather than
being deferrable to later distro work.

Population is per-cataloger: dpkg exposes `Source:` in `/var/lib/dpkg/status`, apk exposes
`o:` (origin) in `/lib/apk/db/installed`.

### D9 — Version comparison stays per-ecosystem

Debian epochs, RPM release ordering, semver pre-release precedence, and Maven ordering
genuinely disagree. A shared `compareVersions` is the specific bug this design avoids.

`Comparer` returns `(int, error)` rather than `int`: version strings from real systems are
sometimes malformed, and silently treating an unparseable version as "not vulnerable" is a
miss. Errors surface as skipped packages with a count, never as clean results.

### D10 — `Finding` carries `Evidence`

Explainability is goal #1. If evidence is not in the type it ends up in log lines, which
means it effectively does not exist.

### D11 — Exit code precedence is contract

```
2 (could not run / cannot be trusted)  >  1 (findings at or above --fail-on)  >  0 (clean)
```

An untrustworthy result outranks the content of the result. Exit codes are a CLI contract —
changing this later breaks other people's CI, so it is fixed now even though the enforcement
that needs it is deferred.

### D12 — Freshness is measured from upstream data, not local build time

`Provenance.DataAsOf` records when the *upstream data* was current, separately from
`Meta.BuiltAt` (when the local database was assembled).

Build time measures the wrong thing. A mirror serving a three-month-old snapshot, fetched
today, produces a build time of today — so a staleness check keyed on build time reports
fresh data that is a quarter old. Air-gapped operation is a stated goal, not an edge case,
so this must be right from the first build.

Age *enforcement* is deferred; the metadata that makes it possible is not, because adding
it later means rebuilding the database.

### D13 — Providers store upstream records losslessly; derived values are computed at query time

Severity bands, for instance, are derived from stored CVSS vectors rather than baked in at
build time. This removes most future "we did not store the field we now need, rebuild the
database" situations. Storage size is not a constraint at this scale.

### D14 — A scan never fetches vulnerability data

`assay db update` is the only command that fetches advisories. A missing or
schema-mismatched database produces exit code 2 with instructions — never an automatic
download, and never a silently empty result.

**Narrowed in slice 2b, deliberately.** This was originally written as "the scan path never
touches the network", which `assay scan alpine:3.19` cannot honour: pulling the image is a
network call on the scan path. The rule it was protecting is about the *database*, not about
sockets — a scanner that quietly downloads advisories is one whose results you cannot
reproduce or audit, and that remains forbidden.

What the narrowed rule still guarantees:

- **No advisory data is ever fetched during a scan.** A stale or absent database is an
  error, not something a scan repairs behind your back.
- **A scan of a local target makes no network call at all.** SBOM files, `docker-archive:`
  tarballs, and `oci-dir:` layouts are fully offline, which is the air-gapped path.
- **Only the target is fetched, and only when the target is remote.** That is visible in the
  argument the user typed: `alpine:3.19` reaches out, `docker-archive:alpine.tar` does not.

### D15 — Malicious-package reports are excluded, but `Advisory.Kind` is not

OSV carries `MAL-*` records — reports that a package *is* malware, rather than that it
contains a vulnerability. Measured against the real dumps (§3.1), they are the overwhelming
majority of the data (see *Measured data volumes* in §3).

Excluding them takes the slice 1 database from ~430 MB to ~86 MB.

They are excluded for now because they are a **different finding class**, not because they
are unimportant. They carry no CVSS severity, so `--fail-on` has no meaning for them, and
the correct report is "remove this immediately" rather than a severity band. Supporting
them properly means designing a second finding class, which is not slice 1 work.

`Advisory.Kind` is added now regardless, because adding a field later means rebuilding the
database. Providers set it; the current filter drops everything that is not
`KindVulnerability`.

**Note that this saves storage, not bandwidth.** OSV publishes one archive per ecosystem
with no server-side filtering, so `db update` still downloads ~244 MB for slice 1 and
discards most of it after parsing.

### D16 — Withdrawn advisories are filtered at ingestion

OSV records carry an optional `withdrawn` timestamp marking a retracted advisory. In the
measured Go dump, 107 of 8,617 records (1.2%) are withdrawn; in a 4,000-record `MAL-*`
sample, 52. Ingesting them produces findings for advisories that no longer stand — plain
false positives.

Providers drop them at ingestion rather than the matcher skipping them at query time, so a
withdrawn advisory cannot leak through a code path that forgets to check.

### D17 — "Unknown" is a first-class severity band

**4,335 of 8,617 Go records (50.3%) carry no `severity` field at all.** This is not an edge
case to paper over; it is half the data.

Absent severity must never be silently coerced to `low` or `none`, because that turns a gap
in the data into a passing build. `unknown` is its own band, outside the
`low < medium < high < critical` ordering rather than at the bottom of it.

Three behaviours follow, and the third exists because the first two are not enough:

1. **Unknown findings are always reported.** A severity threshold filters what fails the
   build, never what appears in the output.
2. **Unknown does not trip `--fail-on <band>` by itself.** With half of all advisories
   unrated, the alternative makes the flag fire on every scan and therefore useless.
3. **`--fail-on-unknown` gates them explicitly.** Without it, (1) and (2) together still let
   an unrated critical vulnerability exit 0 — printed, but passing. That is the same failure
   as coercing to `low`, just louder. The flag is opt-in because defaulting it on would
   reproduce the problem in (2).

```bash
assay scan img --fail-on high                      # unknown passes; count shown in summary
assay scan img --fail-on high --fail-on-unknown    # unknown also exits 1
```

The unknown count belongs in the summary unconditionally, on both output paths — a
threshold that hides how much it could not judge is not a threshold.

Where severity is present it is a CVSS vector. The Go dump contains `CVSS_V3` (3,688) and
`CVSS_V4` (1,100), so the parser handles both from the start — and per D13, vectors are
stored and banded at query time rather than banded at build time.

**The 50% figure may not be permanent.** Records without a CVSS vector frequently alias a
CVE that NVD does score. Joining NVD severity as an enrichment source — the same mechanism
as KISA (D3) — could fill much of the gap. Recorded as a possibility, not a plan.

### D18 — CLI flag names follow grype where the semantics match

`--fail-on`, `--output`, and similar names are shared with grype deliberately. Flag naming
is close to genre convention, familiarity carries over for anyone migrating, and the
differential testing that serves as the primary correctness check (§5) is simpler to script
when both tools take the same arguments.

The risk this creates is not the shared name but **divergent behaviour under a shared name**.
Where assay differs, the difference is documented rather than left to be discovered:

| Flag | Difference from grype |
|---|---|
| `--fail-on` | Same name, same comparison, **different exit code**: 1 here, 2 in grype. grype folds "found something" together with "could not run"; D11 keeps them apart and every unevaluable path in assay already relies on that (D21). |
| `--fail-on <band>` | Band names are `none low medium high critical`; grype's are `negligible low medium high critical`. Same ordering, same positions — assay takes the name CVSS uses for 0.0 rather than the one grype invented (D21). |
| `--fail-on-unknown` | No grype equivalent. Exists because unknown is not in assay's severity ordering (D17). |
| `--fail-on-incomplete` | No grype equivalent. Exits **2**, not 1: a package that was never checked is a statement about coverage, not a finding (D21). |
| severity of a multi-source finding | grype reports one band per match; assay reports every source's and gates on the highest (D25). Measured on Django 3.2.12, 19 findings: grype agrees with assay's aggregate on 19/19 — and with assay's GHSA rating on 19/19, but with its PYSEC rating on 1/15 — counting a band as agreeing only when it is equal, so the 14 misses are grype's real band against PYSEC's `unknown`. On this sample "grype takes the highest" and "grype follows GHSA" cannot be told apart, because PYSEC rates none of them. Separating the two needs a case where a non-GHSA source rates higher. |

Add a row here whenever a shared name gains different semantics. A silently divergent flag
is worse than a differently named one.

---


### D19 — Registry access uses `go-containerregistry`; layer contents stay ours

The second third-party dependency, taken deliberately after measuring both sides.

**What the transport actually costs to write.** An anonymous pull from Docker Hub is three
requests — `401` carrying a `WWW-Authenticate` challenge, a token fetch against the realm it
names, then the manifest with a bearer header — and a working stdlib version of exactly that
is 93 lines. That number is what made writing it look cheap, and it is misleading: it is one
registry, anonymous, happy path. Measured across three registries the flow already differs
three ways — Docker Hub issues a 2,658-character token from `auth.docker.io`, GHCR issues a
52-character one from its own host, and Quay serves public manifests with no challenge at
all. Retries, blob redirects to CDNs that reject the registry's own `Authorization` header,
per-registry error taxonomies, and credential helpers — which are separate executables
spoken to over stdio, not a config file — are all still absent from those 93 lines.

**What it costs to adopt.** Nine modules are linked, 46 packages, and the binary grows from
6.3 MB to 6.8 MB. `go.sum` gains 47 entries, but 38 of those are test and tooling
dependencies of dependencies — `cobra`, `blackfriday`, `opentelemetry`, `testify` — that
compile into nothing. The distinction matters: they are build-time supply-chain surface, not
running code.

`docker/cli` and `docker-credential-helpers` link in even for anonymous-only use, so private
registry credentials arrive with the dependency rather than as later work. That is the
decisive point: the expensive half of writing this ourselves would have been credential
resolution, and adopting the library skips it entirely.

**The boundary.** The dependency buys the registry protocol and authentication and nothing
else. Layer walking, whiteout application, `/etc/os-release`, and `/lib/apk/db/installed`
parsing stay ours — that is the part this project exists to own, and no library does it for
us anyway.

**Layer contents are never written to disk.** A scan needs two files out of each layer, so
layers are streamed and the wanted entries read in passing. Path traversal, symlink escape,
and archive bombs are extraction vulnerabilities; not extracting removes the class rather
than defending against it.

**The Docker daemon source is excluded** (see `docs/deferred-decisions.md`). It alone takes
the linked module count from 9 to 27 and packages from 46 to 114, and it is the least
necessary of the four sources: an image already present locally can be handed over with
`docker save`, which the tarball source reads.

### D20 — The database records which ecosystems it covers

`Meta` carries the set of ecosystem keys the providers report having fetched, and a package
whose ecosystem is absent from that set is **skipped**, never evaluated.

**The failure this closes.** Without it the matcher cannot tell two situations apart: an
ecosystem was ingested and this package has no advisories, or the ecosystem was never
ingested at all. Both look like an empty lookup. Measured on a database holding
`Alpine:v3.19` and scanning the same package twice, changing only the distro release:

```
VERSION_ID=3.19.9  ->  1 finding                                     exit 0
VERSION_ID=3.25.0  ->  "No known vulnerabilities found in 1 package"  exit 0
```

The second is a confident wrong answer, and not hypothetical: OSV's Alpine data stops at
the newest release it has seen, so a release it has not begun publishing hits this.

**Not an Alpine problem.** A database built over Go alone answers a PyPI scan the same way.
The set is checked for every ecosystem, so the guarantee is uniform.

**The provider reports it, because only the provider knows both halves.** Neither obvious
source is right:

- *What the store indexed* over-claims. Records deliberately keep affected entries for
  ecosystems that were not fetched (the cross-ecosystem fix in slice 1), so a store-side set
  built from `Put` certified `Maven`, `NuGet`, `crates.io` and five others on a real database
  that fetched none of them — 9 of 35 keys. The day a Maven comparer lands, that set would
  vouch for a database holding 91 stray Maven keys and every Maven scan would report clean.
  This was written that way first and caught in review.
- *What was fetched* under-claims. `db update` fetches one archive named `Alpine` whose
  records carry `Alpine:v3.2` through `Alpine:v3.24`, so the fetch list names a key nothing
  is ever looked up under and omits the 23 that are.

The provider has both: it knows the family it asked for and sees which release-qualified
keys came back under it. It records the intersection, using the same predicate `Convert`
already filters on, and `SetMeta` unions what the providers reported.

**Coverage is presence, not completeness.** The check answers "was this ecosystem
ingested", not "is the data for it current". A release OSV has only begun populating passes
it. That is the right boundary — freshness is `DataAsOf`'s job (D12) — but it means the
guarantee is "we fetched this", not "we know everything about this".

**Partial coverage keeps the existing exit semantics.** If nothing could be evaluated the
scan exits 2, as it already did; if some packages were covered and others were not, the
uncovered ones are counted and named under "Not evaluated" and the exit code is unchanged.
Making any unevaluated package fail the run is a bigger decision — a single unparseable
version would break a build — and belongs with `--fail-on` in slice 4.

**Schema version 3.** The field is part of the on-disk shape, so a database built before it
is refused with instructions rather than read as covering nothing (D5).


### D21 — Verdicts: what fails a build, and what the exit code means

Slice 4 makes exit code 1 reachable. Four decisions settle what reaches it.

**`--fail-on <band>` exits 1, not 2.** grype's flag of the same name returns 2, folding
"vulnerabilities were found" together with "the scan could not run". Separating those is
what D11 exists for, and the whole project leans on it — every "we could not tell" path
built so far reaches exit 2 precisely so CI can tell the two apart. Matching grype here
would surrender that to save a line of migration notes. Recorded in the divergence table
(D18).

**`--fail-on-incomplete` exits 2, not 1.** A package that was never checked is not a
finding; it is a statement about how much of the target the scan actually covered, and D11
reserves 2 for a result that cannot be trusted. It also lines up with what already happens
when *nothing* could be evaluated — that is exit 2 today, with no flag — so the flag
extends an existing rule to the partial case rather than inventing a second one.

Opt-in, for the same reason `--fail-on-unknown` is (D17): skips are routine. An unparseable
version string, one advisory with a malformed bound, a package in an ecosystem this build
does not support — all of these produce skips on scans that are otherwise fine, and
defaulting the gate on would fire constantly and be turned off.

**Five bands, with `none` at the bottom:** `none < low < medium < high < critical`, plus
`unknown` outside the ordering (D17). CVSS maps 0.0 to None explicitly, and banding derives
from the vector (D13), so the band set follows the specification rather than a tool. grype
calls the same position `negligible`; that is a naming divergence, recorded in D18's table.

Coercing 0.0 up to `low` would be the same distortion D17 forbids in the other direction —
reporting a severity the data does not support.

**CVSS v4 is in scope, and is not a formula.** 6,531 of 27,891 stored vectors are v4 (23%),
and every recent Alpine advisory uses it, so deferring v4 would drop the newest findings
into `unknown` where `--fail-on` cannot see them. But v4 scoring is not a transliteration:
after a macrovector lookup it interpolates using severity distance, macrovector depth, and
a proportional distance averaged across the equivalence classes, with the reference
implementation — not the prose — as the authority.

That makes it the same shape as the apk comparer (D9): an algorithm where a wrong answer is
quiet and a hand-written test table proves little. It must be cross-checked against
published expected scores before it is trusted, and the check must live in the repository
rather than in a commit message.

**Measured, because D17's figure was ecosystem-specific.** D17 says half of all advisories
carry no severity; that is true of the Go dump (49.7%) and of nothing else. Across the
whole database it is 74.9%, and per ecosystem: Alpine 98.9%, npm 89.7%, PyPI 75.9%. A
container scan therefore has almost no unknowns, so `--fail-on-unknown` is far less noisy
there than D17's framing suggests — and correspondingly more useful.

### D22 — Target classification: sniff the content, and let the user override

`assay scan ./bin/assay` is a path that exists, and until now an existing path meant an
SBOM. A binary handed to the CycloneDX parser fails with a JSON error, which sends the
reader to look for a malformed document rather than a misread target.

**Bare paths are classified by content**, in a fixed order: is it a directory, then
`debug/buildinfo`, then CycloneDX. Each test is cheap — buildinfo reads a header and fails
immediately on anything that is not a Go binary — so the order is about determinism, not
cost. In fact the three are mutually exclusive on any real input, so the order is not
observable today; it is fixed anyway, because the day a fourth format is added the
exclusivity stops holding and an unordered sniff would change behaviour silently. A path
that matches nothing is an error naming all three, never a silent fallthrough to one of
them.

**Explicit prefixes override the sniff**: `file:`, `dir:`, `sbom:`, alongside the existing
`docker-archive:` and `oci-dir:`. Sniffing is a heuristic, and a heuristic with no override
is a wall. It also keeps one shape for the whole argument: the target already carries
prefixes for two image forms, and "some kinds are prefixed and some are guessed" is harder
to explain than "guessed unless you say otherwise".

The classifier returns what it decided, and the scan reports it, so a wrong guess is visible
in the output rather than inferred from a confusing error.

### D23 — A directory scan reads `go.mod`, and does not shell out to `go`

Three different answers to "what does this project depend on", measured on this repository:

| Source | Modules | What it is |
|---|---|---|
| the binary, via `debug/buildinfo` | **10** + main | what was actually linked |
| `go.mod` require blocks | **11** | what was requested |
| `go list -m all` | **52** | the whole module graph |

`go list -m all` is the accurate build list, and it is the one we will not use. It requires
the Go toolchain at scan time and, on a cache miss, the network. A scanner that needs a
build toolchain to read a directory cannot run in the environments this is for, and D14
promises an SBOM or archive scan makes no network call at all. Adding a toolchain dependency
to the *filesystem* path would break that promise from a new direction.

So the directory cataloger parses `go.mod` itself, with the standard library. That is
**11 of the 52**, and it is wrong in both directions: it misses transitive modules the graph
would name, and it includes test-only ones the binary does not link — `gotest.tools/v3` is in
this repo's own indirect requires and in no built artifact.

**This is a documented limitation, not a hidden one.** A directory scan says what it read,
and the report recommends scanning the built binary when one exists, because that is the
inventory of the thing that actually ships. Getting a build list without a toolchain means
reimplementing minimal version selection over the module cache, which is a different project.

### D24 — The Go toolchain is a package named `stdlib`

The live database holds **159 advisories against `stdlib`** in the Go ecosystem, with
ordinary version ranges (`introduced="1.16.0-0"`, `fixed="1.16.1"`). A binary built with a
vulnerable toolchain is vulnerable, and `debug/buildinfo` reports the toolchain version, so
declining to match it would be a silent false negative on data we already hold.

`GoVersion` is reported as `go1.26.4` and the advisories use `1.26.4`, so the prefix is
stripped at catalog time. That normalization is load-bearing: the semver comparer rejects
`go1.26.4` outright — measured — so getting it wrong produces a skipped package rather than a
wrong answer, which is at least loud. The pre-release forms are not: `go1.21rc1` and `go1.26`
must normalize to something the comparer orders correctly against `1.21.0-0` and `1.26.0`,
and that is where a quiet ordering bug would live.

Directory scans do not get this. `go.mod`'s `go` directive is a language-version floor, not
the toolchain that will build it, and treating it as one would report a version nothing was
ever built with.

### D25 — A finding carries every source's rating, not one winner

Two databases routinely describe the same vulnerability, and they disagree. Measured over
440 CVE groups reachable from the packages a real scan touches:

| | |
|---|---|
| vulnerability groups (keyed by CVE) | 440 |
| **with more than one record** | **169 (38%)** |
| of those, severity differs between records | 140 |
| of those, the fixed version differs | 152 |

The disagreement concentrates in `GHSA` + `PYSEC` (161 of the 169). Django, from the live
database:

```
CVE-2022-28347   GHSA-w24h-v9qh-8gxj -> critical      PYSEC-2022-191 -> unknown
CVE-2018-6188    GHSA-rf4j-j272-fj86 -> high          PYSEC-2018-4   -> unknown
CVE-2016-2048    GHSA-46x4-9jmv-jc8p -> high          PYSEC-2016-14  -> unknown
```

**Today the matcher keeps the first record it matches and discards the rest**, and "first" is
not a decision anyone made. The package index is a JSON array built with
`ids = append(ids, id)` and never sorted, so the order is whatever order the provider walked
the OSV archives in.

On the current database GHSA happens to come first, GHSA carries CVSS vectors, and the output
is correct — a Django 3.2.12 scan reports critical 5 / high 10 / medium 4 and `--fail-on
critical` exits 1. That is luck. Flip the ingestion order and PYSEC wins: the same critical
findings report `unknown`, and because unknown never trips a threshold (D17), `--fail-on
critical` exits **0**. CI goes green on a critical vulnerability, which is the exact defect
slice 4 exists to remove, reachable through a detail nothing states or tests.

**Re-measured on 2026-08-03**, against the whole database (32,046 advisories, OSV data as of
2026-08-01) rather than the packages one scan touches, and against a real Django 3.2.12 scan:

| | whole database | Django 3.2.12 scan |
|---|---|---|
| vulnerability groups (keyed by CVE) | 19,715 | 19 findings |
| with more than one record | **8,893 (45%)** | **15 (79%)** |
| of those, the severity band differs | **5,693 (64%)** | **14** |
| …because one is rated and another is not | 5,423 | 14 |
| …with both rated, landing on different bands | 306 of 3,530 | 0 |
| of those, the fixed version differs | 2,210 (25%) | **0** |

The severity rows hold, and the split under them is worth reading: almost all of the
disagreement is one source rating what another leaves unrated (5,423), not two sources
scoring the same thing differently (306). That is why `unknown` sitting outside the ordering
(D17) is what makes the aggregate work — a source with no opinion must not be able to
outrank one with an opinion, in either direction.

The fixed-version comparison is the sorted set of every `fixed` event on every `affected`
entry, compared as strings. It over-counts where one record enumerates release branches
another collapses; it under-counts where two records write the same version differently
(`2.2.28` against `2.2.28.0`, a `v` prefix, an epoch), because it never calls a `Comparer`
(D9); and it ignores `last_affected`, so a record that bounds a range that way reads as
having no fix. A tighter definition would need the matcher, at which point it is measuring a
scan rather than the data.

**The fixed-version figure above does not reproduce.** The 152-of-169 recorded in the
original measurement is 90%; re-measured it is 25% across the database and 11% for `GHSA` +
`PYSEC` specifically (510 of 4,488) — the pairing the original sample was 161/169 made of.
Django's fifteen multi-source findings agree on the fixed version unanimously. The original
figure's scope was "the packages a real scan touches", which is not recoverable without that
package list, and the two measurements may not be comparing the same thing: one record can
carry fixed bounds for release branches another omits, which counts as a difference under
one definition and not under the other.

Nothing in D25 rests on it. Ratings carry their own fixed version because a source's
remediation belongs to that source whether or not the sources happen to agree, and the
mechanism is identical either way. The number is corrected here rather than quietly reused,
because a measured figure that reads as authoritative and is not is the same defect the KVE
entry in this document already records.

**So a finding keeps every record's rating.** Not picking a winner removes the ordering
dependency entirely, and turns a hidden disagreement into a visible one — which is what a
scanner whose first goal is explainability should do with two authorities that differ.

**The gate uses the highest band across sources.** This is the rule `severity.Highest`
already applies to several vectors within one record, extended across records: a finding is as
severe as its worst rating. `unknown` does not dilute it, because D17 keeps unknown outside
the ordering rather than below it — so a source that rated nothing cannot pull a critical
finding down to a pass.

**"Source" means the database that authored the record**, not the provider that fetched it.
Those are different: `Advisory.Source` is already `osv` for everything, and will stay that way
while OSV is the only provider. The authoring database — GHSA, PYSEC, GO, ALPINE — is today
only inferable from the identifier's prefix, and a prefix is a naming convention rather than a
field. It is stored explicitly, which is a schema change.

**NVD and KISA are not in this.** assay does not ingest NVD, so it cannot report what NIST
rates something; that is a separate ingestion decision with real cost. KISA is blocked for the
reasons slice 5 records. The mechanism works today with the sources already in hand and
accepts a new one without redesign, which is the point of building it this way rather than
special-casing two names.

### D26 — A directory scan reads every lockfile it finds, and names the ones it did not

D23 settled what a directory scan reads *for Go*. It did not settle what happens to a
directory that is not only Go, and the answer turned out to be the failure this project
exists to prevent. Measured on a directory holding `go.mod`, `package-lock.json` and
`requirements.txt`:

| | components | findings | not evaluated | exit |
|---|---|---|---|---|
| the same packages as an SBOM | 3 | **27** | 0 | 0 |
| `assay scan dir:.` — before | 1 | **3** | **0** | 0 |
| `assay scan dir:.` — after, Python side is `requirements.txt` | 2 | 8 | 0 | 0 |
| `assay scan dir:.` — after, Python side is `poetry.lock` | 3 | **27** | 0 | 0 |

Measured again on 2026-08-03 against a schema-5 database (32,106 advisories, OSV data as of
2026-08-01), same fixture. With a lockfile on the Python side the directory scan now agrees
with the SBOM exactly. With `requirements.txt` it does not — Django's nineteen findings are
still not reported — but the scan says so:

```
scanned dir:. as a directory
go.mod names 1 module(s); this is what was requested, not what a build links - scan the built binary for that
not read: requirements.txt (not a lockfile: versions may be ranges, not resolved versions)
```

That line is the whole of the second half. The 8-finding row is still incomplete, and it is
the one shape where a reader can tell.

Twenty-four findings disappear, and the scan reports `0 not evaluated` while doing it. This
is not "npm and PyPI are unsupported": both are ingested, both have comparers, and both match
correctly through any other path. The directory cataloger simply never looked, and nothing in
the report said so.

That last part is what makes it a defect rather than a gap. D20 already establishes that a
package which could not be evaluated is reported as skipped with a count, so CI can tell
"found nothing" from "was broken". A manifest that is never read produces no package, so
there is nothing for the skip counter to count — the omission is invisible to the very
mechanism built to make omissions visible.

**So the directory cataloger reads lockfiles, and discloses every manifest it recognized but
did not read.** Both halves are load-bearing. Reading them removes the miss; disclosing the
rest keeps the next unread format from being silent in the same way, which is the part that
survives contact with formats nobody has written a cataloger for yet.

**Lockfiles only** — `package-lock.json` and `poetry.lock`. They carry resolved, exact
versions, so unlike `go.mod` they do not inherit D23's requested-versus-linked gap: a
lockfile *is* what gets installed. `requirements.txt` is recognized and named as not read.
It is not a lockfile — `Django>=3.2` is a constraint, not a version — and matching a range
against advisory ranges is a different question than matching a version, one that would
quietly answer "not vulnerable" for anything unpinned. That is a miss, so it waits for a
decision of its own rather than being folded in here.

**A bounded walk, not just the root.** Manifests live in subdirectories — `frontend/`,
`services/api/` — and reading only the root would reproduce this exact defect one level
down, in a repository shape that is completely ordinary. The walk skips `node_modules`,
`vendor` and `.git`, because a lockfile inside a dependency tree describes that dependency's
own requirements rather than this project's, and depth is bounded so a scan cannot be made
arbitrarily slow by directory nesting. Both limits are disclosed the way D23's is.

**The disclosure names the file, not just a count.** "1 manifest not read" tells a reader
that something is missing without telling them what to do; `requirements.txt (not read: not a
lockfile)` tells them which tree is unevaluated and why. Explainability is goal #1 and it
applies to what was *not* checked as much as to what was.

### D27 — NVD is a rating source, joined on the CVE, and never a matching source

Half of what assay reports as `unknown` is not unknown to everyone. Measured over the live
database and NVD's 2.0 API on 2026-08-03: of 8,029 advisories carrying no scorable vector,
a 60-CVE random sample found NVD scoring **93%** of them and rating **48% high or critical**.
Scanning assay's own binary shows what that costs — all three findings are unrated, so
`--fail-on low`, the lowest threshold there is, exits 0, while NVD rates two of them 7.8 and
5.3.

**The join is the CVE, not the CPE.** NVD keys its match data on `vendor:product`, and for a
language package that pair is a curated string no purl can derive: `pkg:golang/gopkg.in/yaml.v3`
is `cpe:2.3:a:yaml_project:yaml`, and `django` splits across two vendors. A dictionary could
in principle be learned by joining OSV and NVD on the shared CVE, but sampled 50 ways it
teaches a trustworthy mapping for Alpine 85%, PyPI 71%, npm 50% and **Go 11%** — and Go
supplies 4,125 of the 8,029 unrated advisories. The CPE-less records are `Deferred`, NVD's
status for what it has decided not to enrich, so waiting does not help. Full findings in
`docs/deferred-decisions.md`.

So NVD answers exactly one question here: *what does NIST score this CVE?* It never decides
whether a package is affected. That stays with OSV and the per-ecosystem `Comparer`s (D9),
and it is why this is a small provider rather than a second matcher.

**It is a Rating, so D25 already defines what happens to it.** An NVD score enters
`Finding.Ratings` as `Database: "NVD"`, the verdict takes the highest band across ratings, and
`unknown` still sits outside the ordering (D17). **Verdicts will change**, and that is the
point rather than a side effect: a finding every OSV source left unrated can now reach
`--fail-on high`. The exit-code contract is unchanged; what changed is that the aggregate has
more to aggregate.

**But an NVD rating is never the displayed record.** D25 says the finding shows the record
that set its band. NVD sets a band without supplying the thing that makes a finding
explainable: there is no range we compared against, no `Evidence`, no fixed version — we
matched through OSV and asked NIST only for a score. Displaying it would put an advisory on
screen with nothing behind it, against goal #1. So D25's rule narrows by one word: the finding
shows the **matched** record that set its band, and an NVD rating can raise the aggregate
without ever being displayed. `--explain` lists it in the per-source breakdown, which is where
a reader looks for exactly this.

**Fetched by `db update`, never by a scan** (D14). ~~A full sync is 187 requests, about 20
minutes at the no-key rate limit.~~ **That estimate was wrong and the live run found it.**

It counted only the rate-limit pauses. Measured 2026-08-03, one 2,000-record page:

| | |
|---|---|
| uncompressed | 4.3 MB, **114.5 s** |
| gzip | 532 KB, **135.8 s** |
| 500 records, gzip | 178 KB, 41.6 s |

Compression cuts the bytes eightfold and does not cut the time, and the cost is roughly
linear per record — so **NVD generates these responses rather than serving a file, and page
size does not change the total**. 372,628 records is therefore about **seven hours**, of which
the 187 rate-limit pauses are twenty minutes. An earlier single sample of 33 s was an outlier
and it is what produced the wrong figure.

Two consequences, both real:

- The HTTP client timeout was two minutes. A real sync died on its first page, because 135.8 s
  leaves no margin at all. It is ten minutes now — measured, not guessed.
- **Seven hours per user is not a database anyone maintains.** So NVD is **opt-in**
  (`NVD_ENABLE`), and `Options.Since` bounds a run with `lastModStartDate`
  (`NVD_SINCE_DAYS`, capped at the API's 120-day window).

  ~~A builder runs one full pass and daily deltas.~~ **It cannot, and the review before merge
  caught this sentence being wrong in the code as well as here.** `db update` builds into a
  fresh database and renames over the live one, so nothing carries an earlier pass forward: a
  bounded run's window is the database's *entire* NVD coverage. Following the recipe as
  written — one full pass, then `NVD_SINCE_DAYS=1` nightly — leaves ~300 ratings where there
  were ~372,000, and every finding whose CVE was not modified yesterday falls back to
  `unknown` with nothing saying why.

  Real deltas need the builder to layer onto an existing database, which is the publishing
  slice's job. Until then the window is **disclosed** rather than claimed away:
  `Provenance.Window` records what a run actually covered and `db status` prints it as
  `COVERED`, because a database holding one day of NVD is otherwise indistinguishable from one
  holding all of it (D20).

### What the first real bootstrap cost, 2026-08-04

Publishing the database meant actually building one, and that took five attempts. Each of the
four failures was a different defect, and none of them was visible by reading the code.

| Attempt | Failed after | Symptom | Defect |
|---|---|---|---|
| 1 | 2m51s | `404` | the window was 120 days **plus the OSV fetch** |
| 2 | 42m | `503` | no retry at all |
| 3 | 116m | `stream error: INTERNAL_ERROR` | retry matched HTTP statuses only |
| 4 | 5h52m | `503` at `startIndex=246000` | 62-second retry budget; notices went to `io.Discard` |
| 5 | **27m26s, succeeded** | — | 30-day window, **23,433 ratings** |

Four things worth keeping:

**`NVD_SINCE_DAYS=120` is not a meaningful reduction.** Attempt 4 reached `startIndex=246000`
of a 372,628-record corpus before dying. NVD keeps touching records — rescoring, adding
references — so 120 days of *modifications* covers most of the feed. The window only shortens
the job at much smaller spans: 30 days is 27 minutes, and that is measured.

**The documented maximum could not be used.** NVD checks the `lastModStartDate`/`lastModEndDate`
span at request time. `Since` was computed when the options were read and the end when the sync
started, and `db update` runs every advisory provider in between — so `NVD_SINCE_DAYS=120`
arrived as 120 days plus minutes and was answered with a bare 404. It is clamped at request
time now, where both ends are finally known.

**A retry budget has to be measured against what giving up costs.** The first schedule totalled
62 seconds, and attempt 4 spent 5h52m before throwing all of it away over a blip. Every value in
that schedule was non-zero, so "each wait is a real pause" was never the property worth
asserting — the budget is. It is ~12 minutes now, which still fits inside the daily workflow's
60-minute timeout.

**Enumerating transient failures only covers the one already seen.** The first retry matched
HTTP status errors, because a 503 was what had just happened; attempt 3 then died on an HTTP/2
transport error surfacing during body decode, and the retry never fired. The policy is a
deny-list now: everything retries except a cancelled context and a 4xx other than 429.

The observability failures are the ones worth being embarrassed about. `Options.Progress`
existed, was documented as the answer to exactly this problem, and was never wired to a writer —
so attempt 4 logged "retries fired: 0" when four had fired. And nothing printed between
`annotating with NVD…` and the result, so the only way to tell a working sync from a hung one
was watching the temporary database grow from outside the process. Both are fixed; neither was
found by a test.

The remaining gap is structural and not fixed: **a failed sync loses everything**. `Update`
builds into a temporary database and installs it only at the end, so attempts 2, 3 and 4
discarded 42, 116 and 352 minutes of completed work. Retries make a page survivable; they do
not make the run resumable. Checkpointing is what would, and it is not built.

The deeper answer is that the full pass should not be every user's problem at all. That is
*Publishing the database as an OCI artifact* in `docs/deferred-decisions.md`, whose revisit
trigger — "CI rebuild time becomes the bottleneck" — this measurement fires. grype and trivy
both work this way: a builder builds, everyone else downloads.

98% of records carry a score. An API key raises the rate limit tenfold and is supported but
not required — it does not change the seven hours, because the bottleneck is NVD's response
generation rather than the pacing.

**Measured against the live feed, 2026-08-03.** A bounded sync — `NVD_SINCE_DAYS=30`, so
CVEs modified in the last thirty days — produced **21,460 ratings** and is enough to settle
the claim, because the findings in question are recent.

`assay scan ./bin/assay`, before and after:

| | before | after |
|---|---|---|
| findings | 3 | 3 |
| unknown severity | **3** | **1** |
| `--fail-on low` | 0 | **1** |
| `--fail-on high` | **0** | **1** |
| `--fail-on critical` | 0 | 0 |

The three findings, after:

```
stdlib                          high     GO-2026-4970 unknown + NVD CVE-2026-39822 high (7.8)
stdlib                          medium   GO-2026-5856 unknown + NVD CVE-2026-42505 medium (5.3)
github.com/klauspost/compress   unknown  GO-2026-5841 - no CVE, so no join reaches it
```

That third row is the 13% arriving in a three-finding scan, exactly as this decision said it
would. It is still `unknown`, still counted in the summary, and still trips no threshold on
its own (D17).

`--explain` shows the narrowing working:

```
severity: high (7.8)   [highest of 2 sources]
  GO     GO-2026-4970    unknown          fixed 1.26.5
  NVD    CVE-2026-39822  high (7.8)       fixed -  https://nvd.nist.gov/vuln/detail/CVE-2026-39822
```

The band comes from NVD; the displayed advisory, the matched range and the fixed version all
come from the record assay actually compared against. NVD's own `fixed` is empty because NIST
published no remediation for this package, and the report says so rather than borrowing one.

**It does not touch coverage** (D20). NVD is not an ecosystem, and `Covers()` must not report
one because NVD scores exist — otherwise a package in an ecosystem this database never
ingested would stop being reported as unevaluated, which is the exact failure D20 exists to
prevent.

**The 13% stays.** 1,008 of the 8,029 unrated advisories carry no CVE at all, so no join
reaches them under any design. That is not a gap to close later; it is the honest ceiling on
this decision, and it showed up as one of the three findings in the binary scan above.

### D28 — The database is built centrally and published as an OCI artifact

One machine builds the database on a schedule and publishes it to `ghcr.io/kun9497/assay-db`;
everyone else runs `assay db update`, which pulls it. `assay db build` still exists and still
builds from the upstream providers — it is now the publisher's command, not the default
end-user path. The artifact's tag is the schema version (`Ref` renders it as `:v8`), so a
binary only ever asks for an artifact it can read: a schema bump produces a clean "not found"
against the old tag rather than a database it would misinterpret, the same guarantee
`store.DefaultPath` already gives the on-disk layout (D5). The artifact's `DataAsOf` is its
**oldest** component's, not its newest (`oldestDataAsOf` in `dbcmd.Push`, folding both
`Meta.Providers` and `Meta.Ratings` into one minimum — a `--seed` build carries `Ratings`
forward without touching `Providers`, so a database whose advisories were just rebuilt but
whose ratings are three months old must publish the ratings' age, not the advisories') — the
same "one stale component makes the whole thing stale" rule D12 already applies within a
single database's own metadata, extended to what gets stamped on the thing that gets
published. **A scan
still never fetches** (D14) — `db update`, `db build` and `db push` are the only three
commands that touch the network on the database side, and a scan reads only what is already
on disk.

**Why this had to happen now, not later.** D27 measured a full NVD pass at about **seven
hours** — NVD generates each 2,000-record page in 114–136 seconds regardless of page size or
compression, so the cost is the API's response generation, not anything a client can tune
away. GitHub Actions caps a job at **six hours**. A scheduled workflow cannot run the build
this decision requires; it can only seed from the last published artifact and layer a bounded
window on top (`NVD_SINCE_DAYS`), which is exactly what slice 8's seeding does and why it
exists at all — publishing without it would ship a pipeline that can never populate the
artifact it publishes. The one full seven-hour pass becomes a local, manual bootstrap: build
once, push once, and every scheduled run after that seeds from what was pushed.

**A schema bump invalidates the published artifact, and the bootstrap is owed again.** The
tag *is* the schema version, so raising `store.SchemaVersion` does not migrate what is
published — it renames the thing every client asks for. `db ref` starts printing `:vN+1` the
moment the bump merges, and until someone builds and pushes a `:vN+1` artifact, `db update`
gets a clean 404 and the scheduled workflow fails with it, because its seed step reads the
same tag. That the failure is loud is the point of tagging by schema at all; the alternative
is a database the binary would misread. But it is not self-healing, and the scheduled build
cannot repair it: that job can only layer a bounded window onto a seed, and there is no
`:vN+1` seed to layer onto. So the one full local build-and-push this decision describes as
the initial bootstrap is owed **on every schema bump**, immediately after the merge — it is a
release step, not a one-time setup step. The KISA enrichment branch is the worked example: it
bumps the schema to v7 while only `:v6` is published, so merging it leaves `db update` and the
daily workflow broken until the v7 artifact is pushed.

**Why `ghcr.io`, and why it costs nothing new.** `go-containerregistry` is already a direct
dependency — the registry `Source` (D-slice 2b) already does auth, manifest handling, and
blob transfer to pull images. Publishing a database as an OCI artifact through the same
library adds no new dependency and no new protocol; it reuses `remote.Write`/`remote.Image`
and `authn.DefaultKeychain` for a second kind of content. This is also the shape grype and
trivy already use — a builder builds, everyone else downloads — so it borrows a proven
pattern rather than inventing a bespoke distribution format.

**Why the seed carries ratings only, never advisories.** `dbcmd.Update`'s seeding step copies
every `Rating` out of the seed database (`Store.EachRating`) before the provider loop runs,
but every advisory is still rebuilt from the providers on every run, seeded or not. The
alternative — copying advisories forward too — would mean an advisory upstream later marks
`withdrawn` could never be removed from a seeded database, because nothing after the seed
step ever re-examines it: D16 drops withdrawn advisories at ingestion specifically so no code
path can forget the check, and a seed that skipped ingestion would be exactly that forgotten
path. Ratings carry no such hazard — `PutRating` overwrites by key, so a stale seeded rating
for a CVE this run's providers also rate is replaced outright, and one this run's providers
did not touch (an annotator that did not run this cycle) still shows its last real value
instead of `unknown`, which is what `db status`'s `COVERED` column is for (D20, D27).

### D29 — Enrichment is built locally, and `db push` strips it before publishing

`db build` fills the `enrichment` bucket from KISA's security notices when `KISA_ENABLE=1`
is set; `db push` empties that bucket on a staged copy of the database and then builds the
file it packs by copying that copy's **live data out** into a fresh one, so the published
bytes never held a record at all. `db update` therefore never delivers KISA's Korean text —
anyone who wants it runs a local `db build`.

**Why.** KISA's site footer reads `Copyright(C) 2026 KISA. All rights reserved.` with no
공공누리 (KOGL) mark (recorded above, under *Terms*). That restricts **redistributing** the
data, not **scanning** with it — a database built and read on the machine that fetched it is
not a redistribution. `db push` is one: it publishes to `ghcr.io/kun9497/assay-db`, a public
registry. So enrichment stays on the machine that built it, and only that local copy ever
carries it.

**The revisit trigger is the licence question resolving** — a 공공누리 mark appearing on the
site, or KISA answering directly that redistribution is permitted. When that happens,
reversing D29 is deleting the `stripEnrichment(staged)` call in `push.go` — the compaction
that follows it copies whatever is live at that point, so with the strip gone the records
simply come across — not restructuring where enrichment lives: it was put in the same bbolt
database as everything
else, keyed `(CVE, Source)` exactly as ratings are, specifically so the reversal would be
that small. A separate file or a separate artifact for KISA data was considered and set
aside for the same reason (see *Splitting KISA data into a separate artifact*,
`docs/deferred-decisions.md`) — that shape earns its cost only once the licence resolves,
and building it now would mean un-building it later if it never does.

**A failing enricher warns; it does not fail the build.** Unlike a `Provider` or an
`Annotator`, whose failure aborts `db build` outright — an unreachable OSV mirror or a broken
NVD sync must not silently ship a partial database — an unreachable KISA endpoint costs a
reader some Korean prose and nothing else: enrichment cannot change a verdict (D3), so there
is no correctness reason to withhold a database over it.

**Six distinct routes to publishing unstripped data were found during review, none by a
test.** Each is now held by one:

1. Deleting the strip call outright.
2. Pointing the strip at the live database instead of the staged copy actually being packed
   — both halves fire at once: the artifact keeps the prose *and* the builder loses its own
   copy.
3. Downgrading the strip's failure from `return 2` to a warning, so a strip that could not
   run still lets the push complete.
4. Gating the strip on `Meta.Enrichment` being non-empty instead of always running it —
   reachable whenever the bucket holds records but nothing recorded a source for them.
5. Letting `--force` override the strip's failure, the way it already overrides `db push`'s
   other refusal (narrowing published coverage). The two guards protect different things: the
   coverage guard protects a database from getting narrower, which a publisher who means it
   may choose to override; the licensing guard protects data that may not be redistributed at
   all, which nobody may override.
6. **Deleting the bucket rather than the data.** Every guard above held — the strip ran, on
   the staged copy, unconditionally, and its failure was fatal — and the published artifact
   still carried KISA's prose. bbolt's `DeleteBucket` **frees** the pages holding those
   records; it does not zero them, and `dbartifact.Pack` reads the whole file and gzips it,
   freed pages included. Measured on this branch: a database with 200 enrichment records,
   stripped in place, still yielded **546** occurrences of their text in the 131,072-byte
   result — `gunzip` on the published layer plus `strings` recovers the Korean verbatim. The
   fix is to stop deleting in place: after the strip, `store.CompactInto` copies the staged
   copy's **live** data into a fresh file (`bolt.Compact`, already a direct dependency), and a
   freed page is not a live page. The order is load-bearing — compacting first would copy the
   records across as live data.

Route 6 is different in kind from 1–5, and so is what it says about testing. The first five
are branches *around* the call; the sixth is the call not doing what its name says.
`TestPush_NeverPublishesEnrichment` could not see it, because it pulls the artifact and asks
`EnrichmentFor`, `EachEnrichment` and `Meta` — the level *above* where the data survives, all
three of which correctly answer "nothing" while the record sits in the file underneath them.
The assertion that holds it scans the **decompressed layer bytes** for the fixture's own text,
which is the same view `gunzip | strings` takes, and no assertion in it goes back through the
bucket API. Reverting to the delete-in-place strip turns that assertion red and leaves every
bucket-level test green — which is the pairing that makes it coverage rather than
documentation.

The recorded ruling is that the current shape — a strip that runs unconditionally on the
staged copy, a compaction that rebuilds the packed file from live data only, both fatal on
failure and neither bypassable by any flag — is safe to merge. The earlier version of this
paragraph said a sixth route would mean the shape of `Push` itself was the problem rather than
its branches, and would call for restructuring rather than one more guard. That is what
happened and that is what was done: the fix changed how the publishable file is *built*, and
added no sixth branch. A **seventh** route would raise the question again, and the answer that
time is more likely to be that the enrichment must not share a file with the published data
at all (see *Splitting KISA data into a separate artifact*, `docs/deferred-decisions.md`).

### D30 — An unreadable entry in `affected[].versions` is skipped and counted, not fatal

`AffectsVersion` walks an advisory's ranges first and falls back to its enumerated
`versions[]` list. When a comparison in that list failed, the whole advisory failed with it.
The two operands mean opposite things and the code conflated them:

- **The installed version** is the left operand and is constant across the loop, so an
  unreadable one really does fail every entry. Skipping on that would turn a total failure
  into a silent clean verdict. It is checked once, before the loop, and still aborts.
- **The listed version** is the right operand and is upstream data. Measured over the v7
  database, 2,411 of 1,309,665 enumerated entries (0.184%) do not parse, poisoning 154
  affected entries. One of them was enough to report a package whose own version is
  perfectly readable as unevaluable against that advisory.

A listed version that will not parse cannot be shown equal to one that will, so skipping it
concludes nothing that aborting would have concluded — it only stops the rest of the list
being thrown away with it. `AffectsVersion` returns the entries it could not read, and the
matcher records a `Skipped` against that advisory exactly as a hard failure does. **That
record is the whole safety argument**: the verdict is now reached over data that was not
read, and without it a loud miss becomes a quiet one. It fires on the "not affected" path
too, because a clean answer computed over an unread entry is just as incomplete as an
affected one.

**The comment this replaces asserted the opposite and was wrong**, which is why it survived
review: it justified failing the advisory by claiming the failure must come from the
installed version, which is exactly the case that still aborts. Reproduced directly —
installed `3.0.0`, list `["1.0.0", "0.9-stable", "2.0.0"]`, and the package comes back
unevaluable because of an entry that is not it.

**Sized honestly.** Of the 154 poisoned entries, **2** change an outcome; the other 152
gain a computed verdict and keep their incompleteness note. What those 2 are worth is
concrete: `asterix-decoder v2.6.0` against PYSEC-2021-860 went from "0 findings, 1 check
could not be completed" to a **critical (9.1)** finding, and **335** installed versions
across the two entries move the same way. The reason to take the change at that size is that
it removes a class rather than a count — new junk arriving in PyPI's enumerated lists can no
longer take an advisory down with it.

**Dropping `versions[]` when `Ranges` is present was considered and rejected.** It would have
rescued 148 of the 154 by never reading the list, and the comment being replaced claimed the
list is redundant when both exist. The data denies it: 1,390 enumerated entries across 19,939
affected entries are not covered by their own entry's ranges. Some of that is upstream
over-breadth — ALPINE-CVE-2018-6196 lists w3m 0.5.4-r0 and 0.5.5-r0 as affected while its
range fixes at 0.5.3_git20241203-r0 — but some corrects a range this walk cannot follow:
PYSEC-2009-17 carries one `introduced` and five `last_affected` events, so the window closes
at the first and only the enumerated list still names plone 3.2 and 3.3. Trading a loud miss
for a silent one is the one thing this package exists to prevent.

### D31 — An apk letter may carry a numeric patch level, and it follows apk-tools 2.x

The apk grammar gains exactly one production — digits, once, immediately after the single
letter:

```
digits ('.' digits)* [ letter [digits] ] ('_' suffix [digits])* ['~' hexhash] ['-r' digits]
                              ^^^^^^^^
```

`libretls 3.3.3p1-r3`, `sudo 1.7.4p6-r0`, `py3-* 0.12.5a0-r0` and `2.1a15-r17` are all real
Alpine package versions that the earlier grammar refused.

**The two apk-tools majors disagree, and 2.x is the one to follow.** apk-tools 2.x parses
these: `next_token()` carries an explicit `*type == TOKEN_LETTER && isdigit(...)` clause
emitting `TOKEN_DIGIT`, and its demotion whitelist names that transition. apk-tools 3.x
rejects them — `token_next()`'s digit case lists only `INITIAL_DIGIT`, `DIGIT` and `SUFFIX`
before `default: goto invalid` — and asserts so in its own vectors (`!0.1a1`, `!0.1bc1`).

Three facts decide it. Every *released* Alpine ships apk-tools 2.14.x; only edge ships 3.x.
Alpine ships the versions regardless. And 3.x's rejection is not a safe conservatism: both
sides of `3.3.3p1-r3` vs `3.3.3p1-r2` reach `TOKEN_INVALID` at the same offset, so
`apk_version_compare_fuzzy` returns **EQUAL** and an unpatched host reads as fixed.
Emulating 3.x here would import that.

**Two properties of the new token are load-bearing.** It is an `apkDigit` — the kind 2.x
uses — and the ordinal matters against `apkSuffix` and `apkRevisionNo`. And it is exempt
from `apkDigit`'s leading-zero string-sort branch: in 2.x that rule belongs to
`TOKEN_DIGIT_OR_ZERO`, the state entered after `.`, while a post-letter digit is a plain
`TOKEN_DIGIT`. So `1.0a01 == 1.0a1`, where a string sort would call them different.

**The hard constraint holds structurally, not statistically.** The new branch can only fire
when a digit immediately follows the letter, and every such string fails the current parser
at its trailing-input check. No version that parses today can reach it, so no ordering that
is correct today can change. apk-tools' own 738-comparison vector file still replays with
736 agreements, 0 mismatches and the same 2 recorded divergences.

**Scope discipline.** apk-tools 2.x accepts more than this rule does, and the extra is bugs
rather than versions: its digit loop accepts an *empty* run, so `1.18.-r2` and `0.8.21.r2`
parse there and the second sorts **above** the `0.8.21-r2` it is a typo for. A second letter
(`1.0a1b2`) and a dot after the patch level (`1.0a1.2`, which 3.x asserts invalid) stay
errors too. The rule is "a letter may carry a patch level", not "be bug-compatible with 2.x",
and the invalid-input table holds that line by name.

**One new over-acceptance, taken knowingly.** `~hash` is a 3.x feature this parser already
implements, so the combination `1.0a1~abcd` is now accepted by neither reference — 2.x has no
hash token and 3.x has no post-letter digit. It appears in no APKINDEX, secdb file or OSV
bound measured. This parser was already a 2.x/3.x hybrid; the combination is the cost of
that, and it is recorded rather than guarded.

**Measured effect.** apk range bounds that will not parse fell from 61 to **39** (30 packages
to 17), and enumerated apk versions that will not parse fell to **zero** — D31 removes the
whole Alpine share of the D30 problem. On an `alpine:3.14` inventory carrying
`libretls 3.3.3p1-r2` and `sudo 1.8.1p1-r0`, the scan goes from **0 findings and 9 checks
that could not be completed** to **6 high-severity findings and none skipped**, including
CVE-2022-0778 and CVE-2019-14287. CVE-2021-3156 correctly stays absent: 1.8.1p1 is below its
`introduced` bound of 1.8.2, which is a comparison that could not even be attempted before.

**The footprint is EOL-skewed and that is worth saying.** The 29 affected APKINDEX entries
are 13 from v3.14/main and 16 from v3.19/community; scanning v3.20, v3.21 and v3.22 across
main and community — 69,893 entries — finds **zero**. libretls is `3.7.0-r2` now. This rule
matters for scanning old images, which is most of what a vulnerability scanner is pointed at,
and it will not grow.

**Two surviving mutations, both verified equivalent rather than untested.** Typing the token
`apkInitialDigit` instead of `apkDigit` leaves the table green: the post-letter token sits at
index 2 or later, `apkInitialDigit` only ever at index 0, and a dotted `apkDigit` can never
align with it because the letter position resolves the comparison first — so ordinals 0 and 1
answer alike everywhere reachable. Likewise `ta.postLetter || tb.postLetter` versus `&&`: the
two flags cannot disagree, for the same reason. Substituting `apkSuffixNo` or `apkRevisionNo`
*does* turn the table red, which is what makes the ordinal claim tested rather than asserted.

**A gap in the upstream check, recorded so it is not mistaken for coverage.** The vector
harness reads only three-field comparison lines, so apk-tools master's validity assertions
(`!0.1a1`) are skipped. The deliberate divergence from 3.x is therefore invisible to the
strongest test this package has, and rests on the reasoning above rather than on that replay.

### D32 — A bare short semver core is a shorthand, padded with zeros

`parseSemVer` pads a core of one or two identifiers to three — but only when the string
carried no pre-release and no build suffix. Everything else is unchanged: leading zeroes
still rejected, four or more identifiers still rejected, non-numeric identifiers still
rejected.

This is verbatim `golang.org/x/mod/semver`'s documented exception — *"recognizes vMAJOR and
vMAJOR.MINOR (with no prerelease or build suffixes) as shorthands"* — and govulncheck already
relies on it to read these same bounds. The data needs it: `github.com/canonical/lxd` is
written at `4.0`, `6.0` and `6.5`, npm's `next` at `13.0`, `github.com/cosmos/cosmos-sdk` at
`0.46`, `github.com/esm-dev/esm.sh` at a bare `136`.

**The bare-form restriction is the rule, not a detail.** `parseSemVer` strips build and
pre-release off the string *before* it splits the core, so by that point `4.0` and `4.0-rc.1`
are indistinguishable; the flag has to be recorded on the way past. Both references refuse
the suffixed form — x/mod's `IsValid` is false for `v4.0-rc1` and `v4.0+meta`, and
node-semver refuses them in strict and loose alike — so padding them would be an invention
neither makes.

**The two references disagree about the bare form, and x/mod is the right one here.**
node-semver rejects `4.0` as a *version* in strict and loose both; it accepts it only as a
*range expression*, where `13.0` means `>=13.0.0 <13.1.0-0`. That reading does not apply:
an OSV `SEMVER` range event is a single version, not npm range syntax. `fixed: "13.0"` means
the release 13.0.0, which is what x/mod's shorthand and node-semver's own `coerce` both
produce. The same rule is therefore right for the Go and npm ecosystems even though one of
the two references would refuse the string outright.

**Leading zeroes were considered and deliberately not adopted.** `19.03.0` (docker/cli, via
GHSA) and `4.072` (neuvector/scanner) stay errors. node-semver throws on `4.072` even under
`loose`, and accepting the shape without also stripping the zeros would be worse than
refusing it: `compareNumeric` orders digit strings by length first, so `4.072` would sort
*above* `4.72` while denoting the same release. That is a silent reordering, which is the
trade this slice exists to avoid. `github.com/docker/cli` therefore remains a loud skip.

**Four or more identifiers stay an error** for the opposite reason to the padding: coercion
would read `1.2.3.4` as `1.2.3`, discarding a component rather than supplying a missing one.

**The OSV sentinel is excluded by name.** `"0"` is a bare one-identifier core and would
otherwise pad to `0.0.0`, which is not what it means — the range layer resolves it to
negative infinity, and a `0.0.0` reading sorts *above* every `0.0.0-prerelease` build and
would drop them out of the window. That protection used to fall out of the three-identifier
check for free, so relaxing that check has to restore it deliberately. This was found by the
existing invalid-input test, which listed `"0"` with exactly that reasoning already recorded.

**The hard constraint holds structurally.** Padding fires only where the parser errors today,
so no version that parses now can change its comparison key or its ordering against any
other.

**Measured effect.** semver range bounds that will not parse fell from 96 to **40** (42
packages to 19); what remains is the leading-zero family and genuinely malformed strings like
`2.10-rc2` and `9.6.0b1`. On an inventory of `lxd v5.0.2`, `cosmos-sdk v0.45.9` and
`next 12.3.0`, the scan goes from **29 findings with 8 advisories unevaluable** to **34
findings and none skipped** — including `next` reaching CVE-2025-29927, which is critical.

Six mutations verified red: dropping the padding, dropping the bare-form guard, dropping the
sentinel guard, padding with `1` instead of `0`, padding only two-identifier cores, and
letting a four-identifier core through.

### D33 — The narrowest KISA notice wins, and its breadth is disclosed

Enrichment is keyed `(CVE, Source)` and every KISA record carries the same source, so a CVE
named by two notices kept whichever page arrived last. Measured live on 2026-08-06, `convert`
produces **20,315** records for **18,524** CVEs: **1,791** were being decided by page order,
the tie-break D25 forbids in as many words.

The winner is now the notice naming the **fewest** CVEs, ties broken on the notice URL. The
tie-break is arbitrary on purpose — the point is that it is a rule at all rather than a
property of the network.

**Selection happens in the provider, not the store.** Only the walk knows how many CVEs each
notice named, and the rule needs the whole corpus: emitting as pages arrive cannot know a
narrower notice is still to come. So nothing is emitted until the walk finishes, and a walk
that fails part-way emits nothing rather than winners chosen from the half it read — which
would be the arrival-order defect again, wearing a rule.

**This is not the store's job, and D13's usual argument does not apply.** Lossless storage
exists so that adding a field later does not mean rebuilding — and enrichment is rebuilt from
scratch on every `db build` in under a minute, never carried forward by a seed. The rebuild
D13 protects against costs nothing here, so keeping the losers would buy nothing.

**The roundup problem is disclosed, not solved, and the measurement is why.** The expectation
recorded when this slice opened was that narrowest-wins would remove the arrival-order
dependence *and* the roundup dilution together. Only the first is true. After selection,
**12,972 of 18,524 records (70%)** still come from a notice naming more than twenty CVEs, and
only **822 (4%)** come from one naming that CVE alone — because for most CVEs the monthly
bulletin is the **only** notice that names them. There is nothing narrower to prefer.

So the mitigation is disclosure. `Enrichment.Claims` records how many CVEs the notice named,
`--explain` prints `scope: this notice covers N vulnerabilities, not only this one` above one,
and the JSON document carries `claims` (schema 3). Without it a bulletin naming a thousand
CVEs and prose written about this one render identically, and the reader has no way to tell
which they are looking at. **Dropping wide notices outright was rejected**: it would discard
70% of the corpus, including the only Korean text those CVEs have, to fix a presentation
problem.

**`Provenance.Records` reports what the database will hold**, not what `convert` produced.
Reporting the larger number would over-claim by exactly the records selection discarded,
which is the thing being fixed (D20's rule, applied to the enricher).

**A third defect turned out not to be one.** 2,202 records (12%) carried a summary beginning
from the no-overview fallback, which read as a parser failure. Measured against 100 live
notices: the exact `□ 개요` heading is present in 65, a looser `□ …개요` form finds 67, and
the remaining 33 have no overview section at all. The fallback is the correct answer for
those, not a miss, and widening the heading match buys two notices in a hundred for a
false-positive risk on every one. Left alone deliberately.

Six mutations verified red: first-notice-wins, last-notice-wins, widest-wins, treating an
unreported breadth as narrowest, reporting the pre-selection count as `Records`, and never
populating `Claims`. The report fixture sets `Claims` to a value that appears nowhere else in
it, because an int left at its zero value lets a renderer that never reads the field produce
byte-identical output.

### D34 — A leading zero in a semver core is normalized away, not refused

A core identifier with a leading zero is accepted and trimmed: `19.03.0` compares equal to
`19.3.0`. This is node-semver's loose mode, verified against 7.8.1 —
`SemVer("19.03.0", {loose:true}).version === "19.3.0"` and
`eq("19.03.0", "19.3.0", {loose:true}) === true`.

**Acceptance and normalization are one rule, not two.** D32 declined to accept the shape
precisely because accepting it alone would be worse than refusing: `compareNumeric` orders
digit strings by length before value, so `4.072.0` would sort *above* `4.72.0` while denoting
the same release — a silent reordering in place of a loud skip. Trimming is what makes the
acceptance safe, and the test table carries the pair whose lengths differ and whose values
agree, because that is the only shape that can tell the two apart.

**A deliberate divergence from `golang.org/x/mod/semver`, which refuses a leading zero
outright.** `19.03.9` is a real Docker tag that Go's own version rules cannot express — part
of why docker is carried as `+incompatible` in the first place — and the string reaches this
code as a GHSA range bound describing a release, not as a module version anything resolved.
Following x/mod here would mean `github.com/docker/docker`, `github.com/moby/moby` and
`github.com/docker/cli` stay permanently unevaluable, which is a worse answer than the one
node-semver gives.

**Not extended to D32's shorthand.** `4.072` and `01.0` stay errors. The two rules come from
different references and neither applies both at once: node-semver's loose *parser* needs
three identifiers and throws on `4.072`, and x/mod's shorthand needs no leading zero. Only
`coerce()` reads `4.072` as `4.72.0`, and coerce is a lossier entry point that also silently
truncates `1.2.3.4` to `1.2.3`. Pre-release identifiers keep the spec's own §9 rule for the
same reason: nothing in the data asks for more.

**Chosen over pep440 leniency on frequency, not on count.** The pep440 residue is larger — 45
bounds against semver's 40 at the time — but it sits on `buildbot`, `trac`, `neutron` and
`asterix-decoder`, packages a real inventory rarely carries. The semver residue sat on
`docker/docker`, `moby/moby`, `go-redis`, `argo-cd` and `grafana`. A bound is worth what it
costs when it fires, and these fire.

**Measured effect.** semver range bounds that will not parse fell from 40 to **12**, across 19
packages to **11** — a larger drop than the bound count suggests, because `19.03.x` recurs
across many docker and moby advisories. `assay` scanning its own binary now reports **no
unevaluated packages at all**, where before it skipped `github.com/docker/cli`;
`v29.5.3+incompatible` is correctly not a finding against a range bounded at 19.03.

What remains is genuinely malformed rather than merely unconventional: `9.6.0b1` (go-redis),
`2.10-rc2` (argo-cd) and `3.0-beta1` (grafana) are missing the hyphen semver requires,
`2018-05-19` is a date, and `1.0.25.1` and `0.4.4.3` carry four identifiers. Guessing where a
hyphen belongs is a different decision from reading a zero-padded number, and there is no
reference to follow for it.

Five mutations verified red: refusing leading zeros again, accepting without normalizing,
dropping the padded-core guard, trimming an all-zero identifier down to nothing, and allowing
leading zeros in pre-release identifiers.

### D35 — Name whose data is unreadable, and repair one documented typo at ingestion

96 range bounds across the three comparers still will not parse. Every one of them sits in a
range that carries another bound that does, so the question was never "is there information"
but "what may be concluded from it". Two changes, and one option rejected on the data.

**Say whose data is at fault.** A malformed advisory bound and an unreadable installed
version both rendered as `not evaluated`, and they mean opposite things to a reader: the
first is nothing they can act on, the second is usually their own inventory. The two are
already separated structurally — `sortEvents` validates every bound before the walk begins,
and it selects the field to validate with the same introduced/fixed/last_affected precedence
the walk uses to select the field to compare — so a failure inside the walk can only be the
installed version. That invariant was load-bearing and unwritten; it is now stated where both
halves can see it, because giving `eventVersion` a different precedence would send an
unvalidated bound into the walk and make the message blame the package for the advisory's
defect.

```
libdwarf 0.5.0-r0 (ALPINE-CVE-2015-8538):
  the advisory's range bound "1999-12-14" could not be read: …
github.com/gogo/protobuf 1.3-broken (GHSA-c3h9-896r-86jm):
  this package's own version "1.3-broken" could not be read, comparing it against
  the advisory's fixed bound "1.3.2": …
```

The matcher's `comparing <version>:` prefix went with it: the package and its version already
head the rendered line, and prefixing every message with the installed version put that string
in front of the ones whose cause is the advisory — the confusion being removed.

**Repair `.rN` to `-rN` for Alpine, at ingestion.** Measured on the v7 database this is
**11** bounds and every apk `fixed` failure there is one of three strings — `0.8.21.r2`
(irssi, 6), `10.2.24.r0` and `10.2.22.r0` (mariadb, 5) — on Alpine v3.3 through v3.8.

It happens at ingestion for D16's reason, so no query path can forget it, and **not** in the
comparer for D31's: apk-tools 2.x does parse `0.8.21.r2`, through a tolerance for empty digit
runs, and orders it *above* the `0.8.21-r2` it is a typo for. Teaching the grammar about the
string would mean adopting that ordering or contradicting the only reference that reads it at
all. Calling it a typo and repairing the datum is the honest description of what is happening.
D31 already recorded that reading, in this document and in the invalid-input table, so this
asserts nothing new.

Two guards carry it. The original must not parse, so nothing already valid is ever rewritten;
and the replacement must parse, so a failed repair leaves the original in place and the error
still names what upstream published rather than something this code invented.

**This does write something upstream did not publish**, which is a real cost against D13. The
alternatives were worse for eleven bounds on two EOL packages: storing both forms complicates
every reader, and threading a repair count out through `Convert`, `Fetch` and the `Provider`
interface is three signature changes. What it gets instead is that the rule is one
substitution in one pure function with the affected set pinned by a table — "what did this
change?" is answerable by reading rather than by trusting. If the repaired set ever grows past
a handful, or a second substitution is proposed, that trade stops holding and the count has to
be plumbed.

**Partial evaluation was considered and rejected on the data.** The obvious rule — treat an
unparseable `introduced` as `0`, since widening a window cannot cause a false negative — is
refuted by the largest single case. Alpine's imagemagick records, 18 occurrences, carry
`introduced 7.0.0-0` (unreadable) beside `fixed 6.9.6.8-r0` (fine): the introduced bound is
*above* the fixed one. Rewriting it to `0` does not widen the window, it inverts it, from
`[7.0.0, ∞)` to `[0, 6.9.6.8)` — losing every 7.x version it was written to cover. The same
objection defeats the more careful version, "answer only when the parseable bounds force the
answer": for imagemagick 7.0.1 the range as written does force *not affected*, and that is a
confident wrong answer, which is the one thing this tool exists not to give.

So 28 apk bounds, 45 pep440 and 12 semver remain loud skips, which is the correct behaviour
for data with no reading. Six mutations verified red; two survive as equivalents, documented
in `repair.go`: no valid apk version can contain `.r` at all, so the already-parses guard can
never change an answer, and `Index` for `LastIndex` cannot either once the second guard
rejects a repair that leaves a later `.r` behind.

### D36 — Incompleteness carries a cause, and the gate can be narrowed to what you can fix

D35 put *whose data is unreadable* in the message. D36 puts it in the type, because a CI
policy deciding whether to fail a build cannot match on prose — and the prose changed one
decision ago, which is the argument in miniature.

`matcher.Skipped` gains `Cause`, one of three:

| cause | means | can the caller act? |
|---|---|---|
| `target` | a version in the scanned artifact will not parse | yes |
| `advisory` | a bound or listed version in the vulnerability data will not parse | no |
| `coverage` | this database or this build does not handle the ecosystem (D20) | sometimes — `db update` |

The classification comes from the `version` package rather than from a string match:
`version.CauseOf(err)` answers `CauseAdvisoryData` or `CauseTargetVersion`, carried on a
wrapper type whose `Error()` delegates, so D35's wording is untouched and this is purely a
second channel for the same fact. An error the package did not classify reports
`CauseUnknown`, deliberately not one of the two real answers: a new error site that forgets
to classify itself has to show up as unknown rather than silently joining whichever side the
zero value names.

**The gate is added, not changed.** `--fail-on-incomplete` keeps meaning "anything went
unchecked", because exit codes are contract (D11) and quietly narrowing an existing flag
would stop failing pipelines that rely on it. `--fail-on-incomplete=target` is the narrow
form, and `=any` spells out the default so a pipeline can say which it means rather than
relying on the bare form continuing to mean the broad one. An unrecognized scope is an error,
not a silently disabled gate.

**Why the narrow form has to exist.** 85 range bounds in the live database are malformed
upstream data — `1999-12-14` as a version, `7.0.0-0` in an Alpine record, `9.6.0b1` missing a
hyphen — and no amount of fixing the scanned artifact changes any of them. A pipeline gated on
`--fail-on-incomplete` that meets one of those is red on every run until somebody turns the
gate off, and **a gate that gets turned off protects nothing.** Measured on `libdwarf 0.5.0-r0`
against the v7 database:

```
--fail-on-incomplete           exit 2     (an advisory bound nobody can fix)
--fail-on-incomplete=target    exit 0     (nothing wrong with the scanned artifact)
```

...and on an SBOM carrying `github.com/gogo/protobuf 1.3-broken`, `=target` exits 2.

`Summary.TargetIncomplete` carries the count and `SkippedRecord.cause` carries the per-record
value (report schema 4), so a policy that wants only its own broken input filters on
`.cause == "target"` rather than on the reason text. `TargetIncomplete` cuts across both
existing counts rather than being a subtotal of either — a whole-package skip the caller
caused must gate too, and a gate reading `IncompleteChecks` would miss it.

**An unclassified error maps to `advisory`, not `target`.** The conservative direction is the
one that does not tell someone their input is broken when we do not know that, and it also
keeps an unclassified error inside the default gate rather than quietly outside it.

Nine mutations verified red, including both directions of the mapping, tagging the uncovered
ecosystem as the caller's fault, counting every skip as the target's, reading
`IncompleteChecks` in the narrow gate, `=target` setting the broad flag, and accepting an
unknown scope silently. One initially survived — stripping the cause tag off the advisory-bound
error, which the matcher's conservative default made invisible. It is now held by asserting
`CauseOf` in the `version` package directly, since that answer is that package's contract
regardless of what any caller defaults to.

### D37 — KISA enrichment is on by default, and the publish workflow turns it off

D29 made `KISA_ENABLE` opt-in and gave a reason: the data may not be redistributed, so an
off-by-default flag is the honest shape for something a user has to choose to hold. That
reasoning protected the wrong person. `db push` strips enrichment either way, so an opt-in
flag never guarded redistribution — it only guarded against *having* the feature, and the
person it kept it from was the one who wanted it and forgot the variable. This project exists
to attach KISA's Korean prose to findings; that was off by default for everyone including its
author, which is how the question came up.

So the default flips. `db build` fetches KISA unless told not to, and `KISA_ENABLE=0` is how
you tell it. Nothing about D29 changes: `db push` still strips, `db update` still never
carries it, and the artifact is still byte-identical to what it published before.

**The publish workflow sets `KISA_ENABLE=0`, and that is the point of the flag now.** Turning
enrichment on there would mean 41 requests to a public-sector service, every day, for data
`db push` deletes seconds later — worse than pointless, since the cost lands on somebody
else's servers.

**The off switch had to be built before the default could move.** The shape being replaced was
`os.Getenv(name) != ""`, under which `KISA_ENABLE=0` means **on**. That was survivable while
both flags were opt-in and nobody had a reason to write a falsy value, and it stops being
survivable the moment a workflow depends on "0". `envFlag` reads `1/true/yes/on` and
`0/false/no/off`, case-insensitively and whitespace-trimmed, because YAML quoting varies and
`KISA_ENABLE: "0"` must not arrive as `" 0 "` and mean the opposite.

**An unrecognised value warns and takes the default rather than failing.** This is a database
build, not a scan: refusing to start over a malformed environment variable would trade a fetch
nobody wanted for a build nobody got. The warning names the variable and the value, on stderr
with the rest of the build's diagnostics.

**NVD stays opt-in**, now through the same reader. Its gate is about cost — a full pass is
about seven hours — and starting one nobody asked for is a different kind of surprise from a
fetch that takes a minute. Sharing `envFlag` means `NVD_ENABLE=0` now works too, which it did
not before.

Seven mutations verified red: KISA back to opt-in, NVD flipped to default-on, `"0"` no longer
disabling, case sensitivity dropped, whitespace not trimmed, an unrecognised value disabling
instead of defaulting, and the warning removed.

### D38 — `requirements.txt` is read, and only the lines that name one version become packages

D26 left it unread and gave the reason: `Django>=3.2` is a constraint, not a version, and
putting a range inside an advisory range would quietly answer "not vulnerable" for anything
unpinned. That reasoning is intact. What changes is the conclusion drawn from it — refusing
the *file* to avoid guessing at *some lines* threw away the ones that need no guessing.

A line becomes a package iff its specifier set is a **single** clause whose operator is `==`
(with no `*`) or `===`. Everything else is counted, named, and left unevaluated.

**A requirements file is a list of pip install arguments, not a manifest** — pip's own
framing, and the reason a parser built on PEP 508 alone is already wrong. The grammar is
argparse *around* PEP 508: options, includes, editable installs and bare paths share the file
with requirement specifiers, and each has to be recognized in order to be refused honestly.
pip's preprocessing order is reproduced rather than approximated — join continuations, then
strip comments, then drop empties — because reversing the first two lets a trailing comment
swallow the backslash and glue two requirements into one.

**`#` starts a comment only at line start or after whitespace.** pip's own `COMMENT_RE` is
copied rather than approximated with `strings.Index`, which would destroy `#egg=`,
`#subdirectory=` and `#sha256=` fragments mid-URL.

**`==3.2` is a pin and `==3.2.*` is not.** PEP 440 zero-pads the release segment before
comparing and PyPI normalizes on upload, so `3.2`, `3.2.0` and `3.2.0.0` are one release, not
three — `==3.2` names exactly one and reaches neither `3.2.1` nor `3.2.0.post1` nor `3.2a1`.
The wildcard form is a prefix match: a range wearing an `==`.

**Multi-clause sets are refused even when they do pin.** `Django==3.2,!=3.2.1` really does
name one version. Admitting it means admitting multi-clause sets, and the first draft of that
rule — "exactly one `==` clause, all others `!=`" — let `foo==1.4.*,!=1.4.1` through, because
the wildcard exclusion had been written into the single-clause branch only. A review found it;
a rule with no multi-clause case cannot have it.

**This follows pip-audit, not syft.** syft's `guessVersion` rewrites `*` to `0` and takes the
*maximum* of a `>=` bound, inventing a version the file never stated. trivy gates on the
operator. pip-audit — from PyPA itself — refuses an unpinned requirement and reports it as a
skipped dependency. A fabricated version is a confident wrong answer in both directions: too
low and a fixed package reads as vulnerable, too high and a real vulnerability reads as fixed.

**Environment markers are dropped, not evaluated.** Evaluating `python_version < "3.8"` needs
the environment the code will *run* in, and all this process has is its own — so a marker that
is false here says nothing about the deployment. Reporting a package a marker excludes is a
false positive, which is loud; refusing every marked line is a silent gap in a shape the corpus
shows is common. `${VAR}` is refused outright for the same reason inverted: pip expands it from
its own environment at install time, and expanding it here would invent a version.

**Includes are components, not options.** `-r base.txt` is reported as unevaluated rather than
ignored. A file whose every line is an include would otherwise catalog nothing and report a
clean scan — the shape a review measured at 1.8% of a sampled corpus, and exactly the silent
miss D26 exists to prevent.

**What could not be used is named, not only counted.** "3 package(s) with no version to
compare" does not say which three, and pinning them is the action being asked for:

```
not pinned: requirements.txt: flask>=2.0 (not pinned to one version: >=2.0)
not pinned: requirements.txt: -r base.txt (includes another requirements file, …)
```

**And it closes a hole D36 left.** `--fail-on-incomplete=target` counted only the matcher's
skips, so the cataloger's own — a component with no usable version or no purl, which is the
scanned artifact's data by construction — reached no gate. An unpinned requirement is the
clearest case that flag exists for, since "pin it or give us a lockfile" is precisely an action
the caller can take. `SkippedUnsupportedEcosystem` stays out: that one is assay's coverage.

**Measured.** A seven-line requirements.txt against the live database: **23 findings** where
before there were none, three lines named as unpinned, `--fail-on-incomplete=target` exiting 2
until they are pinned and 0 once they are.

Eleven mutations verified red, including the wildcard admitted as a pin, multi-clause admitted,
the naive comment cut, an environment variable silently accepted, `-r` treated as an option
rather than a component, unusable lines counted but not named, options counted as components,
requirements.txt returned to unread, cataloger skips dropped from the target scope, an
unsupported ecosystem added to it, and the disclosure removed.


### D39 — There is no upstream vector file for semver or PEP 440, and the hand tables are stronger than the corpora that exist

The apk comparer replays apk-tools' own 738-comparison vector file, and that replay caught a
defect the hand-written table had missed. semver and pep440 had no equivalent, which made them
look like the weakest of the three. **They were not, and this decision is mostly the
measurement that says so.**

**No conformance corpus exists.** There is no semver equivalent of `JSON-Schema-Test-Suite` or
`yaml-test-suite`; every implementation carries its own table, and the semver specification
repository is eleven files of which none is a fixture. Recorded so the negative result does not
have to be rediscovered.

**`golang.org/x/mod/semver` is a silently wrong oracle.** It implements *Go module* semver,
where the leading `v` is mandatory: `IsValid("1.2.3")` is false, and x/mod then orders every
invalid string as equal to every other — so `Compare("1.2.3", "1.2.4")` returns **0** where this
package returns -1. Not an error, an ordering. OSV's SEMVER bounds carry no `v` prefix, so the
class is not exotic: measured over 5,546 real strings, **1,143 (20.6%)** are accepted here and
rejected there. Importing it would also make a third direct dependency, but that was never the
deciding objection.

**packaging's `VERSIONS` list is blind where it matters most.** 92 entries yielding 4,186
ordered pairs — and only **four distinct release strings** among them (`1.0`, `1.0.1`, `1.1`,
`1.2`). Verified by mutation: a comparer that compares release segments **lexically** passes all
4,186 pairs and still says `1.9 > 1.10`. That is the most common false negative in version
comparison and exactly what a scanner meets — an advisory bounded at `< 1.10.3` against an
installed `1.9.x`. This package's own table already carries `{"1.10", "1.9", 1}`. Replaying a
corpus weaker than the table it would check is worse than not replaying it.

**What was added anyway, and what it is worth.** node-semver's `comparisons.js` is replayed
under the existing build tag: 31 pairs, ISC, parseable with one regex because the file is a pure
array literal — unlike its sibling `invalid-versions.js`, which needs a JavaScript engine. Its
`equality.js` is inverted into a **negative** fixture, because 31 of its 37 entries are npm
input-normalisation cases (leading whitespace, an `=` prefix, `v 1.2.3`) that a scanner's
comparer must refuse rather than accept. And both specifications' own ordered chains are
transcribed offline — 55 semver pairs and 136 PEP 440 pairs, every pair rather than only
neighbours, with antisymmetry asserted alongside.

**Measured yield: zero.** Every one passes on first run, and mutation says why — the pre-release
rank inversion, numeric-versus-alphanumeric rank, build metadata as a tiebreaker, the `=` prefix,
epoch, post/dev order and dev rank are each caught by the *existing* table as well as by the new
ones. Nothing added here catches anything the hand tables did not already catch.

They are kept as a **tripwire, not as coverage**: node-semver is the dialect D34 deliberately
follows, so the replay fires if npm adds a case this package gets wrong or if a future edit
diverges from it — and its divergence list is empty rather than counted with a tolerance, so the
first divergence is a decision somebody writes down. The offline chains cost no network and
check transitivity, which a table of independent pairs does not.

The README line calling these two "the weakest point of the three" is corrected: the weakness
was an untested assumption about the tables, and testing it is what this decision did.


### D40 — The Debian comparer is a transliteration of dpkg, checked against dpkg

`internal/version/deb.go` is a line-by-line transliteration of `verrevcmp` and `parseversion`
(dpkg's `lib/dpkg/version.c` and `lib/dpkg/parsehelp.c`), not an interpretation of
deb-version(7). The two agree, but the algorithm is the normative artefact and the prose is
loose exactly where it matters.

**Debian is the ecosystem where a subtle ordering bug is most likely and most costly.** `~`
sorts BELOW the end of a string, which no other ecosystem does:

```
1.0~~  <  1.0~~a  <  1.0~  <  1.0  <  1.0a
```

Getting it backwards makes every backport and release candidate compare on the wrong side of
its own base — `1.2.3-4~bpo11+1` reading as newer than `1.2.3-4` is a silent miss on exactly
the systems that took the security fix. Two more rules break intuition: every letter sorts
below every other punctuation mark (`1.0z < 1.0.0`, because `z` ranks 122 and `.` ranks 302),
and leading zeros are stripped from digit runs before comparison, so `1.09` and `1.9` are one
version.

**The oracle is the real dpkg binary, not a file.** dpkg ships no machine-readable vector file
— its vectors live inside a Perl test module and a C unit test — but `dpkg --compare-versions`
is on every ubuntu-latest runner, which is a better oracle than a file and costs no network.
Unlike the apk replay it has **no known-divergence list and must not grow one**: apk falls
back to a string sort for input it cannot parse, a guess this project deliberately refuses,
while dpkg either parses a version or rejects it. A disagreement is a defect.

Alongside it: 39 table rows (upstream dpkg vectors plus real strings from `debian:bookworm`,
`gcr.io/distroless/base-debian12` and Ubuntu 24.04), 14 invalid inputs, 15 valid-but-unusual
shapes, and the Policy chain over all 66 pairs with transitivity and antisymmetry.

**Three rows of that table were wrong on first run and the comparer was right every time**:
`1.2.3` equals `1.2.3-0` (dpkg strips the revision's leading zero, leaving both empty),
`1.0-2-3` is valid under the last-hyphen split, and `+b1` sorts BELOW `+deb11u1` because `b`
ranks 98 and `d` ranks 100.

### D41 — The version compared is the one belonging to the name that reached the advisory

D8's comment said indirect matching needed no version adjustment, "because an Alpine binary
package carries its source package's version". Debian breaks that, and the break is
systematic rather than exotic:

| binary | binary version | source | source version |
|---|---|---|---|
| `bash` | `5.2.15-2+b13` | `bash` | `5.2.15-2` |
| `bsdutils` | `1:2.38.1-5+deb12u3` | `util-linux` | `2.38.1-5+deb12u3` |

A binNMU rebuilds a binary without touching the source, and the second row drops an epoch the
binary carries. **13–15% of Debian packages differ this way**, against about 1% on Ubuntu —
Debian binNMUs where Ubuntu rebuilds with a new revision — so a fixture built only on Ubuntu
would exercise it about once.

OSV's Debian advisories are source-keyed and carry SOURCE fixed versions; every packaged purl
in the archive is `?arch=source`. Comparing a binary version against one of those is comparing
two strings from different counters that happen to look alike.

So the matcher compares `Source.Version` when the advisory was reached through the source
name, and `Version` otherwise. An empty `Source.Version` means "the same as the binary
version" — what `dpkg-gencontrol` omits the field to say, and what apk's origin always implies
— so Alpine reaches exactly the answer it did before.

### D42 — Debian only; Ubuntu needs its own decision

**Debian encodes its backports in the version**: `7.74.0-1.3+deb11u10`. 169,282 (CVE, source,
release) triples were joined against Debian's own security tracker and **zero disagree** —
OSV's Debian data is a faithful mechanical transform of the tracker, not an independent
re-derivation.

> **Correction, measured 2026-08-07 (D43).** This paragraph originally opened "The Red Hat
> warning does not transfer to Debian. Red Hat backports fixes and omits that from the
> version, which is why `docs/deferred-decisions.md` records RHEL as blocked." That contrast
> was wrong in both halves. Red Hat encodes the backport too, in the advisory's fixed version
> (`0:8.7p1-38.el9_4.1` for regreSSHion), and all 588,150 fixed events in its OSV export carry
> an epoch and a release. Debian's advantage over RHEL is not backport encoding — it is that
> `Debian:12` is derivable from `/etc/os-release` while Red Hat's key is one of 903 CPE-derived
> variants, and that Debian's feed can express an unfixed vulnerability while Red Hat's OSV
> export is errata-only. The measurement above stands; only the comparison drawn from it was
> wrong.

Ecosystem keys are the bare major, `Debian:11` through `Debian:14`, which is what both OSV and
`/etc/os-release`'s `VERSION_ID` use. **testing and sid carry no `VERSION_ID` at all** and OSV
publishes no ecosystem for either, so they are a loud skip: inventing `Debian:14` would
compare against fixed versions sid does not ship.

**Ubuntu is deliberately excluded.** OSV keys it `Ubuntu:24.04:LTS`, and its Pro and FIPS
lineages — `Ubuntu:Pro:FIPS-updates:18.04:LTS` — describe the *same release*. A release-only
key cannot separate them, so a scan of an ESM-patched system would match the non-ESM lineage's
fixed versions and report it vulnerable. That is a systematic false positive, and it needs a
decision about lineage keys rather than a second case in the ecosystem mapping. The corpus is
also 6.03 GB unpacked against Debian's 254 MB, which the provider would have to stream.
(Both figures were misquoted here until D53 measured them: Debian's 383 MB was an on-disk
block count, and the multiplier is affected entries per record, not `versions[]`.)

**Distroless images are named, not silently empty.** They keep the database in
`var/lib/dpkg/status.d` as a DIRECTORY, and `source.Image.Files` takes exact paths. Those
images reach the "no supported package database" error, which names the shape it cannot read.
Reading them needs a prefix walk in the image layer reader, which is its own change.

The cataloger reads deb822, not RFC822: whitespace before the colon is legal, field names
match case-insensitively (the exact opposite of the apk database's `P:`/`p:` rule), and
continuation is ANY whitespace — syft tests only for a leading space, so a tab-continued field
becomes a new field, fails to find a colon, and is silently dropped. Installed-ness is decided
on the THIRD word of `Status` and nothing else, which is how syft drops
`deinstall ok installed` by substring-matching and trivy drops `purge ok installed` by
scanning for a bare word. An absent `Status` means installed, because every package in a
distroless image is in that state.

### D43 — RHEL-family targets are inventoried and refused, not matched

An image whose `/etc/os-release` names an RPM-family distro has its package list read and
reaches **exit 2**. The reader, the RPM header parser and the comparer ship; no provider does,
so no RHEL finding is ever emitted.

**Why the inventory without the matching.** The obstacle recorded against RHEL — that Red Hat
backports fixes and its OSV data therefore carries upstream versions — is wrong, and D42's
correction above records the measurement. But a different property of that feed blocks
matching: **it is errata-only.** Zero of 588,150 affected entries lack a fixed version, so
"affected, will not fix", "fix deferred" and "out of support scope" cannot be represented at
all. Red Hat's CSAF VEX feed carries 62,983 CVEs against OSV's 23,668; **39,372 exist only in
VEX, 19,341 of them from 2023 onwards**, and 37–43% of two independent samples name a base-OS
RPM as `known_affected` with no fix. Matching on this feed returns a clean verdict for every
one of them. That is D20's failure one level up — not "the ecosystem was never ingested" but
"the ecosystem was ingested and cannot say the thing that matters".

Two further obstacles are recorded in `docs/deferred-decisions.md` rather than here, because
they shape the provider rather than this slice: the ecosystem key is one of 903 CPE-derived
variants and the support channel it encodes is a subscription attribute with no filesystem
representation, and the modularity label is absent from every one of the 588,150 purls.

**No new exit rule was needed, and that is the point.** `Summary.Trustworthy()` already
returns false when `Components > 0 && Evaluated == 0`, so a RHEL image whose 186 packages are
all catalogued unkeyed reaches exit 2 through the guard slice 4 wrote. Adding a RHEL special
case would have been the wrong instinct — the general rule already covers it, and a test that
proves the guard fires on this path is worth more than a second code path that agrees with it.

**"RPM distro detected but no rpmdb found" is a hard error, never an empty inventory.**
`/var/lib/rpm` is a *symlink* on RHEL 10, Fedora and CentOS Stream 10, whose real database
lives at `/usr/lib/sysimage/rpm` (Fedora 36's RelocateRPMToUsr). A reader that probes only the
traditional path finds nothing in the layer tar, and without this rule an image with 172
packages would report as having none. Both paths are probed.

**AlmaLinux and Rocky Linux are not shortcuts**, despite keying on the bare major. AlmaLinux
carries zero `aliases` and zero `upstream` across all 5,494 records — every CVE is in
`related`, which OSV defines as explicitly not an alias — so under D3 it yields **0 CVEs**, and
it has no severity data at all. Rocky's export has a median 0.29 coverage of Red Hat's runtime
package set and **no record whatsoever for CVE-2024-6387**. Neither changes this decision
(RHEL 8/9/10 still route to Red Hat's own CSAF feed, not to either rebuild's OSV export) — but
see D71 and D72, where both distros later got their own routing to their own archives instead.


### D44 — The rpmdb is read by hand, not by dependency

Both backends, in this repository, with no addition to `go.mod`: SQLite b-tree with overflow
chains for RHEL 9+, and BerkeleyDB hash for RHEL 8 and older. Roughly 750 lines plus the shared
RPM header parser.

**The argument is that a scanner only ever enumerates.** rpm's own read-only BerkeleyDB backend
is ~850 lines of C because `rpm -q openssl` is a point lookup and needs the hash index. This
never looks a package up by name, so the index, the btree backend and the entire SQL layer are
dead weight — a sequential page walk recovers every record. Validated: 185 packages from
`redhat/ubi8` and 107 from `amazonlinux:2`, each matching the count in the format's own
reserved key-0 record, and on the SQLite side all 188 blobs from `ubi9` byte-identical to what
real SQLite returns across seven images.

**The dependency is expensive exactly where writing it is cheap.** `modernc.org/sqlite` costs
4 modules, 136 packages, ~217,000 compiled lines of transpiled C and 3.8 MB of binary, and buys
only the SQLite backend — the one that is 294 lines to write. `anchore/go-rpmdb`'s BDB and NDB
backends are pure stdlib and pull nothing, which is the same conclusion arrived at from the
other direction.

**`SOURCERPM` gives D8 its indirection for free.** `audit-3.1.5-8.el9.src.rpm` yields source
name `audit` after stripping `.src.rpm` and the last two hyphen-separated fields. Across seven
images every real package resolved a source name; `gpg-pubkey` rows are keyring entries with no
arch and are filtered.

**NDB was not implemented, at this point.** It is openSUSE/SLES only, no Red Hat lineage uses
it, and there was no SUSE advisory provider for it to serve. The first half of that reasoning
stopped holding — D76 reads it — while the second half (still no SUSE advisory provider) has
not changed.


### D45 — A write-ahead log or a damaged page is a hard error, and the guard reads the file, not the header

**rpm always uses WAL mode.** Every `rpmdb.sqlite` checked — ten of them — carries file-format
write and read version bytes of exactly 2, the SQLite encoding for WAL. So a guard written as
`if h[18] > 2 || h[19] > 2` can never fire, and the reader silently returns whatever the main
file held when the log was last checkpointed.

This is not hypothetical. A research prototype shipped that exact guard, with a comment above
it reading *"refuse rather than silently report a stale package list"*, and it was demonstrated
wrong: against a database with a live 28,872-byte WAL holding one newly inserted package, real
SQLite returns 189 rows and the reader returned **186, `skipped=0`, exit 0, no error**. A second
run with 40 deletions in the log returned 186 against a true 148. An installed package invisible
to a vulnerability scanner is the silent miss this project exists to prevent — and the guard
that was supposed to stop it was the CLAUDE.md antipattern in its purest form: declared,
documented as the thing that prevents the defect, and unable to fail.

**So the guard is on the sibling file.** A `rpmdb.sqlite-wal` larger than its 32-byte header
means the main file alone is not the current database, and the read is refused. This forces the
reader's signature to reach the sibling file rather than taking a bare `io.ReaderAt` — an API
consequence, not an `if` statement, which is why it is recorded rather than left to
implementation.

**Page-level damage is refused the same way.** An `ubi9` database with page 41 overwritten by
`0xFF` — the rootpage of the `Recommendname` index, one of roughly twenty tables the file
actually holds, not the one the prototype assumed — produced 186 packages and no error where
real SQLite reports the image as malformed. Structural checks cover the whole file, not only
the pages the `Packages` walk happens to touch.

**A test is not enough on its own here.** Both defects above passed a suite that named them.
Each guard added under this decision must be verified by making the failure real — a fixture
with an actual non-empty WAL, a fixture with an actually corrupted page — and confirming the
suite goes red before the guard lands.


### D46 — RPM version comparison is its own comparer, and an absent epoch is zero on both sides

A fourth `Comparer` implementing `rpmvercmp`, per D9. It is not dpkg with different separators:
`~` sorts below everything as in Debian, but `^` sorts *above*, alphabetic segments compare
below numeric ones, and the segment splitting differs. Upstream's `rpmio/rpmvercmp.cc` is a
115-line function body, and full EVR comparison adds `epoch:version-release` splitting on top.

**The highest-risk row in the table is the absent epoch, and it is absent on both sides.**
AlmaLinux omits the epoch when it is zero (52,290 of 67,076 fixed events) while Red Hat and
Rocky always emit it; on the installed side, 145 of 158 real packages in `almalinux:9`'s rpmdb
carry no `EPOCH` tag at all. So `7.76.1-23.el9_2.4` and `0:7.76.1-23.el9_2.4` are one version
and a comparer that string-compares them, or that treats a missing epoch as anything other
than 0, is wrong in whichever direction the data happens to fall. The table must also cover
`.el9_4.1` against `.el9`, `module+el8.5.0+12582+56d94c81` against
`module_el8.5.0+119+9a9ec082`, `0:208-20.ael7b_1.9` against `0:208-20.el7_1.9`, and
leading-zero stripping.

Written in the main loop with the table reviewed line by line, per CLAUDE.md's delegation
rules: a subtle ordering bug here is a silent false negative, which is the exact failure the
per-ecosystem design exists to prevent.


### D47 — The Red Hat ecosystem key is the mainline major, because that is the only one a scan can derive

`Red Hat:9`, from `/etc/os-release`'s `VERSION_ID` major, matched against the union of every
`cpe:/[oa]:redhat:enterprise_linux:9` product — bare, and at any `::baseos`, `::appstream`,
`::crb`, `::server`, `::client`, `::workstation` or `::computenode` repository below it.

**The alternative is not available, rather than merely harder.** Red Hat's VEX archive carries
**462 distinct CPE shapes** across 903 exact keys: mainline, `rhel_eus`, `rhel_aus`,
`rhel_tus`, `rhel_e4s`, and per-minor variants. Those describe the same releases with
different fixed versions — and **which one applies to a host is a subscription attribute with
no filesystem representation.** `/etc/os-release` says `9.8`; nothing on disk says whether the
subscription is EUS. Restricting to mainline drops the share of (CVE, package, major) groups
that resolve to more than one fixed version from **25.1% to 6.1%**.

**The filter is an anchored regexp, not a prefix match**, because unrelated products share the
namespace: `cpe:/a:redhat:openstack:10::el7`,
`cpe:/a:redhat:jboss_enterprise_application_platform:6` (9,118 entries),
`cpe:/a:redhat:satellite:6::el7`, `cpe:/a:redhat:ceph_storage:5`. So do near-misses that a
loose pattern would swallow: `enterprise_linux_nvidia` and `enterprise_linux_eus` are
different products whose names merely begin the same way.

**RHEL 10 uses a per-minor mainline CPE** — `cpe:/o:redhat:enterprise_linux:10.2` — where 8
and 9 use the bare major. A pattern written for the common shape drops 244,865 records
silently, so the minor is accepted and folded into the major.

**Module builds are dropped and counted**, not stored. The release string records the platform
build and a context hash but NOT the stream name, so `nodejs:18` and `nodejs:20` are
indistinguishable from `1:20.20.2-2.module+el9.6.0+24220+c44c288d` alone. 19.1% of mainline
groups are module-tagged and modules cause 69% of the fixed-version ambiguity that survives
the mainline filter. `('CVE-2021-20291', 'buildah', '8')` resolves to two fixed versions from
two streams of `container-tools`: taking the higher is a systematic false positive, taking the
lower is a false negative, and there is no third answer available from the data.

**The disclosure this owes.** An EUS, AUS or E4S host is matched against mainline errata, which
can name a fixed version that host's channel never shipped. That is a known, bounded divergence
rather than a hidden one, and it belongs in the report when RHEL findings are emitted.


### D48 — Affected with no fix is a range with no fixed event, reported always and gated only on its own flag

Red Hat says a package is affected at every version it ships and there is nothing to upgrade
to. In CSAF that is a `known_affected` product ID carrying a **bare package name** where a
`fixed` one carries a full NEVRA:

```
cpe:/o:redhat:enterprise_linux:5   mailman                     <- affected, no fix
cpe:/o:redhat:enterprise_linux:9   openssh-0:8.7p1-38.el9_4.1  <- fixed
```

**In OSV shape that is a range with an `introduced` event and no `fixed` one**, which the
store already understood and the matcher already evaluates. Nothing in the schema changed to
accept it, and that is the second confirmation of D1's claim that owning the schema is what
makes a non-OSV provider possible — the first being KISA.

**The measurement that decided the gating.** Of the 1,995,138 mainline records this feed
yields, **1,292,054 (65%) have no fix**. Red Hat 9 alone carries 552,599 of them across 2,935
packages. But the distribution is not flat — counted per source package on Red Hat 9:

```
glibc 0   openssl 7   systemd 1   bash 0   coreutils 2   curl 27
libxml2 9 krb5 1      sqlite 2    python3 21   tar 10    zlib 1
kernel 4491
```

A container image has no kernel, so an ordinary image scan gains something in the low hundreds
— a lot, but not a flood, and every one of them is a real vulnerability a security team should
know about. A HOST scan gains 4,491 from the kernel alone, which would bury everything else.

**So these follow `unknown`'s rule exactly (D17).** They are always reported and always
counted in the summary, they never trip `--fail-on <band>` on their own, and they reach exit 1
only through an explicit `--fail-on-unfixable`. The precedent is deliberate: the mechanism is
already in the codebase, already understood, and already argued — D36 records what happens to
a gate that is red on every run and cannot be fixed, which is that somebody turns it off, and
a gate that is off protects nothing.

**Not reporting them was never an option.** That is the OSV export this provider exists to
replace.


### D49 — The VEX archive is read as zstd, which costs no dependency

Red Hat publishes one full archive, `csaf_vex_YYYY-MM-DD.tar.zst`, named by
`archive_latest.txt`. There is no gzip variant and no per-year split; the alternative is 63,071
individual document fetches.

**`github.com/klauspost/compress/zstd` is already linked into the binary.**
go-containerregistry pulls it for zstd-compressed image layers, and `go list -deps ./...`
showed the zstd package in the build before this provider existed. Promoting it costs **one
line moved from `go.mod`'s indirect block to its direct one**: `go.sum` is byte-identical, the
module count is unchanged at 52, and the binary grew 56 KB — this provider's own code. It is
the same shape as D28, where publishing the database as an OCI artifact cost no new dependency
because go-containerregistry already carried registry auth and blob transfer.

**Everything is streamed and nothing is written to disk.** The archive is 262 MB compressed and
**17.1 GB decompressed across 67,261 documents, the largest of them 94 MB**. The document
struct is deliberately narrow because `encoding/json` skips absent fields without allocating,
so the two biggest parts of a real document never materialize: `product_tree.relationships`
(2.8 MB of CVE-2024-6387's 4.7 MB, and unnecessary — a product_status entry already spells
`platform:component`) and `product_status.known_not_affected` (4,476,026 entries archive-wide,
and nothing downstream can use a not-affected claim).

**Freshness comes from the archive's name** (D12). `csaf_vex_2026-08-05.tar.zst` names the day
Red Hat built it. A name with no readable date is fatal rather than falling back to
`time.Now()` — substituting the fetch time for the data time is exactly what D12 forbids.

**The archive is a snapshot, and a delta pass follows it.** Red Hat rebuilds
`csaf_vex_YYYY-MM-DD.tar.zst` on its own schedule while individual documents change in between,
so a database built from the archive alone is behind by however long that has been. It is not a
theoretical gap: on BOTH differential runs against grype — ubi9 and ubi8 — every finding grype
had and assay did not came from documents written after the archive, and nothing else did.

`changes.csv` lists every document with its last-modified time, **newest first**, so the scan
stops at the first row older than the archive's own date rather than reading all 62,989.
Measured 2026-08-07 against a 2026-08-05 archive: **1,827 documents**, roughly 900 per day of
drift. The cutoff is the archive's DATE at midnight rather than its build time, which nothing
publishes — that over-fetches by up to a day, and over-fetching is the harmless direction
because `Bolt.Put` keys on the advisory ID. The delta is emitted AFTER the archive walk so
last-write-wins is the newer document.

Only a 404 is survivable: `changes.csv` and `deletions.csv` are written separately, so a
document withdrawn between them is a race. Everything else fails the build, because a pass that
exists to close a known gap and quietly closes part of it leaves the database looking complete
while sitting somewhere in between.

**Opt-in via `REDHAT_ENABLE`, for a third reason.** Not redistribution: the feed is TLP:WHITE
on all 67,261 documents, so unlike KISA (D29) what is built from it can be published. Not
runtime either: 90 seconds, against NVD's seven hours. What makes it opt-in is **size of
result** — roughly 1.9 million affected entries added for users who may never scan a RHEL
image. D37's argument for defaulting KISA ON was that it costs almost nothing and changes
nothing for anyone not looking at it; this is the opposite case.

**The counters are split by cause, and finding out why is worth recording.** The first run
against the real archive reported *"9,430 unreadable"*. Not one document had failed to parse.
They are `known_affected` entries from Red Hat's pre-2005 releases — `Red Hat Linux 6.2`,
`Red Hat Powertools 7.0`, `Red Hat Enterprise Linux AS (Advanced Server) version 2.1` — that
name a **product and no package at all**. A category, not a failure. One counter serving two
causes produced an alarming number that was wrong and would have been believed.


### D50 — Only `rhel` is matched against Red Hat's errata

`/etc/os-release`'s `ID` decides, and only `rhel` resolves to a `Red Hat:N`
ecosystem. Every other RPM distribution is still catalogued — the rpmdb is read and
every package listed — and every one of them is reported as not evaluated, so an
unrouted distribution is a loud skip and never a clean verdict.

Routing on `ID` rather than on the `elN` release string is the load-bearing part.
`ubi9`, `almalinux:9` and `rocky:9` all carry `el9` release strings, and only the ID
tells them apart.

**Each exclusion is a different reason, not one blanket caution:**

- **AlmaLinux and Rocky** are rebuilds, but not byte-identical ones. Alma writes module
  builds as `module_el8.5.0+119+9a9ec082` where Red Hat writes
  `module+el8.5.0+12582+56d94c81`, and its own rebuilds carry `.alma` release suffixes.
  Comparing one distribution's installed versions against another's advisory versions is
  the hazard `docs/deferred-decisions.md` records against both. They also have their own
  OSV feeds, whose separate problems that entry records: AlmaLinux carries zero `aliases`
  and zero `upstream` so D3 yields 0 CVEs from it, and Rocky has no record at all for
  CVE-2024-6387.
- **`centos`** is one ID covering two products that sit on opposite sides of RHEL.
  CentOS Linux trailed it; CentOS Stream runs *ahead* of it, so a fix that has not
  reached RHEL yet is already in Stream. The same key would be wrong in opposite
  directions for the two, and nothing in `/etc/os-release` separates them reliably.
- **Fedora and Amazon Linux** have different version schemes and their own advisory
  feeds (`FEDORA-*`, `ALAS-*`). Red Hat's errata do not describe them at all.

**Revisit when** a provider exists for the distribution in question. This is a routing
decision, not a permanent judgement: the moment AlmaLinux's own feed is ingested under
an `AlmaLinux:N` key, an `almalinux` ID routes there and nothing here changes.


### D51 — The published artifact carries the Red Hat data, and `REDHAT_ENABLE` defaults on

`db push` publishes whatever the database holds, and from now on that includes Red Hat's CSAF
VEX records. Nothing had to be added to make it publishable: the feed is **TLP:WHITE on all
67,261 documents**, so unlike KISA (D29) there is no strip step and no licence question.

**What it costs, measured 2026-08-07 on the same machine.** The download is what a user feels;
the disk figure is the bbolt file `db update` leaves behind.

| | without Red Hat | with |
|---|---|---|
| artifact download | 20.9 MB | **28.7 MB** |
| database on disk | 512 MiB | 1.07 GB |
| `db build` wall clock | ~10 min | **~28 min** |

The download grows by 37% and the disk by roughly double. The download was the number that
decided it: 8 MB more for the only source that can say a RHEL package is affected and will not
be fixed is a trade worth making for everyone, including the people who never scan a RHEL
image and pay only the 8 MB.

**`REDHAT_ENABLE` therefore defaults ON**, reversing what D49 recorded. A default that
disagreed with the artifact would mean `db build` and `db update` produce different databases,
and `db push`'s coverage guard would refuse the narrower one — a refused daily publish is a bad
way to discover a default. `REDHAT_ENABLE=0` still turns it off for a local build that does not
scan RHEL and wants to be twenty minutes shorter. The publish workflow sets it explicitly all
the same, so changing the default later cannot silently narrow what is published.

**The daily job had to be made to fit first.** The delta pass was 1,827 sequential requests and
about nineteen minutes. They are latency-bound, so fetching eight at a time takes it to about
four, and the whole build to 28 minutes; the workflow's timeout goes from 60 to 120 minutes.
Documents are still emitted IN ORDER — the store's last-write-wins is what makes a re-emitted
advisory replace its own record, so an out-of-order pass would make which version survives
depend on which request finished first.

**Two defects came out of that concurrency, and neither came out of review.** Cancelling left
the producer goroutine wedged on a semaphore token nobody would return — a leak rather than a
wrong answer, which is why nothing caught it until a mutation did. And a `select` whose cases
are both ready picks at RANDOM, so watching for cancellation only inside it made stopping
probabilistic: the test asserting otherwise failed three runs in ten, and checking `ctx.Err()`
at the top of the loop made it 12 for 12.


### D52 — A range carries why it has no fix, and the gate can be narrowed to "never"

**Decision.** `advisory.Range` gains a `FixState`. Red Hat's CSAF remediation categories fill
it: `no_fix_planned` becomes `wont-fix`, `none_available` becomes `not-fixed`. The report shows
the three cases apart, and `--fail-on-unfixable=wont-fix` gates on the first alone.

The store's schema goes to 8, which under D5 means every database is rebuilt rather than
migrated.

**Why it was worth a rebuild.** Two thirds of what Red Hat publishes about its own packages is
"affected, no fix" — 1,282,093 of 1,927,642 mainline tuples in the 2026-08-09 archive — and
until now assay printed one sentence for all of it. Inside that mass are two different
instructions. "Red Hat will not fix this" leaves mitigation or removal and nothing else; "no fix
yet" is a reason to watch the CVE. A reader who cannot tell them apart has to treat every
unfixable finding as either permanent or temporary, and both readings are wrong most of the
time.

On a real image the split is not a rounding error. Measured with grype, which already carries
the distinction:

| Image | Findings with no fix | Of those, will never be fixed |
|---|---:|---:|
| ubi9:9.3 | 416 | 11 (2.6%) |
| ubi8:8.9 | 505 | 59 (11.7%) |

On ubi8 that is roughly one line in nine, concentrated in packages an image actually ships —
`vim-minimal` (7), `ncurses-base` and `ncurses-libs` (12 between them), `openssl-libs` (3).

**The distinction turned out to be fully carryable, which was not a given.** The measurement
that decided this was not the split but the coverage: of those 1,282,093 unfixable tuples,
**every single one** is named by a `no_fix_planned` or `none_available` remediation. Zero carry
neither. Had a large fraction been uncategorised, most findings would have stayed "no fix
available" whatever the schema did, and the rebuild would have bought a label for a minority.
`stats.UnfixableUnstated` counts that bucket on every sync so the day it stops being zero is
visible rather than inferred.

**The state sits on the range, not on the package or the advisory.** A package can be fixed on
one release and permanently affected on another — `TestConvert_FixedAndUnfixedTogether` was
already a fixture for exactly that shape before this slice — and both ranges are emitted side by
side. A field on `Affected` would have to pick one of the two and silently drop the other. A
field on `Advisory` is worse still: one CVE routinely spans many packages with different
answers.

**`fixed` is derived, never stored.** A range that has a `fixed` event is fixed, and writing
that down a second time creates two copies of one fact that a later ingestion bug can make
disagree. `matcher.fixStateOf` resolves it from the evidence instead, which is D13's rule
applied to a field D13 would otherwise have no opinion about.

**Unknown is a state, exactly as D17 has it for severity.** Only Red Hat publishes a reason
today. An OSV range with no `fixed` event records that no fix is known — not that a vendor
intends one — so those stay `unknown` and render as they did before this slice. Nothing about a
non-RHEL target changed. In the store, unknown is the empty string, because it is the
overwhelmingly common case and a repeated word across a million ranges is real bytes on a
database already running 1.07 GB; `matcher.fixStateOf` is where that spelling stops, so no
renderer has to know the two are the same answer.

**Both categories on one package resolve to `wont-fix`, deliberately.** 179 of the 1,282,093
tuples carry both — 0.014%, every sampled one `kernel-rt` on RHEL 9, a package that ships many
parallel point-release variants and appears in no container image. The tie is broken by a stated
rule rather than by arrival order (D25), and toward `wont-fix` because the two errors are not
symmetric: calling something permanent when a fix later lands is a false alarm the next scan
clears, while calling it temporary when nothing is coming leaves the reader waiting on a fix
that does not exist. `stats.UnfixableBothReasons` discloses the count, so a feed that began
disagreeing with itself in bulk would show rather than be resolved 179 times in silence.

**Names follow grype (D18)** — `fixed`, `not-fixed`, `wont-fix`, `unknown`, and
`FindingRecord.fixState` in the JSON — so a differential run compares field to field. Two of
grype's own habits are not copied. Its table renders `not-fixed` and `unknown` as the same empty
cell, which throws away most of the distinction at the last step; assay prints `no fix yet`,
`none` and `won't fix` as three visibly different strings. And its one filter setting answers to
three different names (`--ignore-states`, config `ignore-wontfix`, env `GRYPE_IGNORE_WONTFIX`);
`--fail-on-unfixable=wont-fix` is spelled one way.

**The gate is a scope on the existing flag, not a new one**, following D36's
`--fail-on-incomplete=target`. Bare `--fail-on-unfixable` keeps its meaning exactly, so no
existing CI changes behaviour, and `=any` spells that out for a pipeline that would rather say
which it means than rely on a default never moving. The narrow form exists for the reason D48
gave for not making the broad one a default: Red Hat contributes 4,491 unfixable kernel findings
on RHEL 9 alone, a gate that is red on every run gets switched off, and a gate that is off
protects nothing. `=wont-fix` fires on the tenth of that where waiting is not a strategy.

**`group_ids` is counted, not expanded.** CSAF lets a remediation name a product group instead
of listing products; Red Hat does not use it — 0 of 63,152 documents in the 2026-08-09 archive,
and no `product_groups` block to resolve one against. Implementing an expansion no data
exercises would ship an untested path; `stats.RemediationGrouped` makes a feed that started
using it visible instead, and the affected packages would degrade to `unknown` rather than to a
wrong answer.

### D53 — Ubuntu is keyed on its mainline release, and a lineage build is skipped rather than judged

**Decision.** `Ubuntu:22.04:LTS` and `Ubuntu:25.10` are the only Ubuntu keys this build stores
and the only ones `version.For` resolves. The Pro, FIPS, FIPS-updates, FIPS-preview, Realtime
and Nvidia-BlueField lineages are dropped at ingestion. A package whose own version carries a
lineage marker — `+esmN`, `~esmN`, `+FipsN` — is reported as not evaluated instead of being
compared against mainline advisories.

No schema change: the key is a string in a field that already exists.

**The version scheme was never the blocker.** D40's dpkg comparer handles Ubuntu revisions
(`2.4.4-2ubuntu17.10`) unchanged, the dpkg cataloger already populates `Package.Source` from the
same field, and the matcher's source lookup is ecosystem-agnostic. Unlike Debian and Red Hat,
nothing had to arrive alongside the comparer except the key.

**The lineages are the problem, and the measurement reversed what this project expected.** The
deferred entry predicted a false positive: a release-only key matching the non-ESM lineage's
fixed versions and reporting an ESM-patched system vulnerable. Measured against the live export
on 2026-08-10, the observable direction is the opposite and it is unanimous. Of the (CVE,
package) pairs at one release carrying both a mainline and a lineage fixed version, **67 of 67
differ, and in 67 of 67 the lineage version sorts strictly higher**. The mechanism is
mechanical rather than incidental: Canonical builds a FIPS package by appending `+FipsN` to the
identical base version, and dpkg orders a `+`-suffixed string above the string it extends. So
mainline's fixed version is always the lower bar, and a mainline-only scan of a FIPS host reads
clean when it is not. On a real image that is 72 of 136 (CVE, package, lineage) triples at
22.04 and 14 of 23 at 24.04, **every one in the silent-miss direction and none in the other**.

That number proves mainline-only cannot certify a FIPS host. It is not a measurement of how
often a deployed image is misscored, because no Pro/FIPS image is anonymously pullable and none
was tested — which is worth stating plainly rather than letting the 72 read as more than it is.

**Detectability is where Ubuntu differs from RHEL, and it differs in the dangerous direction.**
D47 refused to guess RHEL's support channel because no filesystem signal exists at all. Ubuntu
writes real files when a subscription is attached — an apt source, a credential, a machine
token. But **Canonical's own documented way to build a FIPS or ESM container image deletes every
one of them**: attach, install the patched packages, detach, purge the client, all inside one
`RUN` so the token never reaches a layer. What ships is patched binaries and no trace of the
entitlement. A scanner reading "no config" as "mainline" would be wrong on exactly the images
built the way Canonical says to build them — a heuristic that looks like it works in testing and
fails quietly in production, which is worse than RHEL's flat "never available".

**So the signal is the installed version string, which the install itself bakes into the dpkg
database and no purge removes.** `[~+]esm\d` is what syft matches for the same reason, and its
own comment calls an installed `+esmN` package the durable signal. `+FipsN` comes from
Canonical's advisory data, where a FIPS fixed version is the identical base plus the suffix. The
match is case-insensitive because Canonical writes `Fips` in a version and `FIPS` in an
ecosystem key, and missing one spelling would report every FIPS package clean.

**Skipped, not guessed at.** A lineage package becomes a `SkipCoverage` entry: counted, named in
the report, and reaching exit 2 through `--fail-on-incomplete`. That is D47's answer to the same
question, and the reason it is right here too is that the alternative is not "slightly wrong" —
it is confidently clean on a compliance host, which is the one place a scan result is load
bearing.

**Realtime and Nvidia-BlueField are not covered and are not claimed to be.** Those lineages
differ by package NAME (`linux-realtime`, `linux-bluefield`) rather than by a version suffix, so
this detector cannot see them. A container image ships no kernel, so the gap is a host-scan one.
It is recorded in `docs/deferred-decisions.md` rather than papered over with a name list nothing
has measured.

**Dropping the lineage entries at ingestion is what makes the corpus affordable.** Ubuntu's
export is 601 MB compressed and 6.03 GB unpacked against Debian's 70 MB and 254 MB. The driver
is not record count — 62,751 against 62,465, near enough identical — but **38.9 affected entries
per record against Debian's 3.4**, because each record lists one entry per (lineage × release ×
binary package). Version lists are not the cause: they are 23.2% of Ubuntu's bytes against 49.5%
of Debian's.

Stripping affected entries is the thing that broke this provider once before, so the drop is
written to be safe for the reason that bug gives rather than in spite of it. What made stripping
lossy was that another PASS had already indexed the entries being dropped. No pass ever indexes
an Ubuntu lineage key: `Ecosystems` never names one, `familyMatches` can never return true for
one, and `version.For` refuses to resolve one. An entry dropped here is unreachable by
construction, not merely unreached today — and it is dropped on every fetch rather than only the
Ubuntu one, so the invariant does not depend on pass ordering.

**The lineage predicate is "Ubuntu but not mainline", not a list of the six families.** OSV's
schema documents only the bare `:Pro:` prefix; every other spelling is convention, and two
non-canonical shapes are already in the live export
(`Ubuntu:22.04:LTS:for:NVIDIA:BlueField`). A list would silently start storing whatever family
is invented next.

**The LTS suffix is read from PRETTY_NAME**, because OSV keys a long-term release
`Ubuntu:22.04:LTS` and an interim one `Ubuntu:25.10`, so the suffix is part of the key. The
tempting alternative — infer LTS from an even year and an `.04` month — is already wrong on a
shipping key: 25.04 is an April release and is not long-term. Reading a free-text field is
acceptable only because the failure is loud: a wrong key names an ecosystem the database does not
hold, and D20's coverage check turns that into a whole-package skip and exit 2, never a clean
verdict.

**Neither grype nor trivy solves this**, which is worth recording because it means there is no
prior art to follow. Both read Canonical's Launchpad tracker through their own pipelines, where
lineage is a per-package pocket annotation rather than a competing top-level key, so the
ambiguity never arises for them. Holding D1 — every provider normalizes into OSV shape — is what
gives assay a problem neither had. grype carries exactly one Ubuntu channel, `esm`, and excludes
FIPS and Realtime deliberately as separate compliance products.

### D54 — A distroless dpkg database is a directory, and the layer walk learned to enumerate one

**Decision.** `Image.FilesUnder(dir)` returns every regular file directly inside a directory,
across layers, with the same rules `Files` applies to a named path. `scancmd` uses it to read
`/var/lib/dpkg/status.d` when `/var/lib/dpkg/status` is absent, and `dpkgdb.ParseStanza` —
which already existed for this shape — parses each stanza.

**Why a new method rather than more paths.** `Files` takes exact names, which is right for the
three databases a scan wants by name. It cannot express this one: the contents of `status.d` are
named after the packages, which is what the scan is trying to find out. The set has to be
discovered, and that is a different operation rather than a longer list.

**The layer rules are not optional here either.** Newest layer wins per path; a whiteout hides
lower layers but not its own; an opaque marker replaces the directory wholesale. A distroless
image built by copying one base's `status.d` over another's is exactly where those decide the
inventory, and getting the second wrong makes an upgraded package vanish entirely — a silent
miss rather than a wrong version.

**Direct children only.** `status.d` is flat. Recursing would hand this cataloger files from
some future image shape that it would then try to parse as dpkg stanzas. A prefix match would
also pull in `status.d.old`, which is the same class of mistake the existing rule against
globbing `status*` guards — `debian:*` ships `status-old` holding a duplicate of every stanza.

**A symlink under the directory is counted, not followed**, and the count joins
`skippedRecords`, so it reaches `Summary.TargetIncomplete` (D36). Following one would mean a
resolve pass per entry against a set that is itself being discovered, and no distroless image
measured carries one. It also shadows a lower layer's regular file at that path: the link is
what the image ships, and substituting the shadowed file would report a version the image does
not have. Zero is the expected count; a non-zero one is something a reader can act on.

**Tried only when the single-file database is absent**, so an ordinary Debian image pays nothing
— `FilesUnder` is a second full pass over every layer. An image carrying both is not a shape
anything ships, and preferring the file leaves the existing path untouched.

**The known limitation is unchanged and is the one `Files` already has:** a symlink on a
DIRECTORY COMPONENT of the path is not followed. If some image made `var/lib/dpkg` itself a
link, this would find nothing and the scan would refuse with its "no supported package
database" error rather than report clean.

### D55 — SARIF puts the skips where the consumer will see them, not only where the spec says

**Decision.** `--output sarif` writes SARIF 2.1.0. Packages that could not be evaluated are
emitted **twice**: as `invocations[].toolExecutionNotifications[]`, which is the spec's own
channel for what a tool has to say about its run, and as `note`-level results under an
`assay/not-evaluated` rule. Unrated findings carry no `security-severity` at all.

**The duplication is the decision.** GitHub code scanning does not support `invocations` — the
field is absent from its supported-properties tables entirely. A document that disclosed its
skips only there would satisfy the spec and show a reader nothing, which is the shape this
project keeps finding in its own tests: something that names the right thing and cannot be
seen. The obligation is the one every renderer here carries — a partial scan must not read as a
complete one — and a `results` array is the only place the consumer that matters looks.

Verified against a real Rocky Linux 9 image, which D50 catalogues and refuses to route: 146
packages, **146 note-level results, 147 notifications, `executionSuccessful: false`, exit 2.**
Zero findings serialises to an empty `results` array, and an empty array is what a clean scan
looks like; that is the failure this shape prevents.

**An unrated finding gets no `security-severity`.** GitHub's scale starts above 0.0 and has no
room for unknown, so the only way to fill the field is to invent a band. Writing 0.1 would show
the finding as low and be indistinguishable from a real low one — the coercion D17 exists to
forbid, arriving through a format's constraint rather than through the matcher. The property is
omitted and the result still carries `level: warning`, because a finding nobody rated is still
a finding and `none` reads as informational.

**Fingerprints identify the finding, never its version.** GitHub requires
`partialFingerprints` to track a result across commits, and keying one on the installed version
or a file offset would close every alert and open an identical one the moment a package moved —
on a vulnerability that is still unfixed. The hash is (advisory id, ecosystem, package, matched
name), and the key names the scheme so a later change ships as a new key rather than silently
re-identifying everything.

**Two things grype's SARIF drops are carried here.** Its `help.text` prints an empty
`Fix Version:` for every unfixed finding and says nothing about whether one is coming; this
writes a sentence and puts D52's `fixState` in the rule's properties, so the wont-fix / not-fixed
distinction survives into the format a reviewer actually reads. And the message names the
source package when D8 matched through one: a SARIF file is read in a web UI detached from the
command, where "libssl3 is affected by an openssl advisory" is otherwise unverifiable.

**Hand-rolled structs rather than a SARIF library.** The format is large, this uses a corner of
it, and a third direct dependency is a real decision this does not justify.

### D56 — `db build` says where it spent its time

**Decision.** Every provider, annotator and enricher is timed, and `db build` prints a summary
to stderr: slowest first, with each stage's share of the wall clock, its record count, and the
remainder that belongs to no stage.

**Why now.** The nightly publish went from 29 minutes to 85 after Ubuntu landed (D53), and one
run was cancelled at the 120-minute timeout with nothing in the log to say which provider to
blame. Raising the timeout without that is guessing at which stage to raise it for, and the
obvious suspect is not always right — the Red Hat delta looked like the expensive part until it
was measured and turned out to be latency, which 8-way concurrency cut from 19 minutes to 4.

**Slowest first, not run order.** The question this output answers is always "what do I fix"
and never "what ran when"; run order is already visible in the `fetching`/`annotating` lines
above it.

**A failed stage is listed with its elapsed time and marked, never omitted.** A provider that
died after forty minutes is the most useful row in the table, and a summary printed only on
success is guaranteed to be missing from every run where it would have mattered. That claim had
no test until a mutation removing both failure-path calls left the package green.

**The gap between the stages and the wall clock is named.** A build whose stages sum to a
fraction of its total is saying the bottleneck is somewhere this table does not look — store
opening, seeding, coverage, the final rename — and an unexplained gap reads as the stages being
the whole story. The row is omitted when there is nothing in it, because "everything else 0s"
on every build trains the reader to stop seeing the line.

**To stderr**, with every other diagnostic: the database path on stdout is what a script reads.

### D58 — A transient delta fetch is retried; a permanent one still fails the build

**Decision.** One document fetch in the delta pass gets three attempts, 0.5s then 1s apart.
What is transient and what is not is the whole decision, and it lives in one function.

**Why.** A single closed connection killed a 42-minute build on 2026-08-13, on document
2,448 of a delta pass: `cve-2026-64179.json: EOF`. D49's rule is unchanged and is why
that hurt — only a 404 yields nil, everything else fails the build rather than quietly
closing part of the gap the delta exists for. What that rule did not do is separate "the
feed is gone" from "the socket hiccuped", and D51's 8-way concurrency made the second more
likely by raising the request count.

**Both directions of misclassification cost.** Retrying a PERMANENT error turns a changed
feed into a slow build that fails anyway and buries which document broke under three
identical failures. Not retrying a TRANSIENT one is the bug.

Retried: transport failures, 429, 5xx, and a body cut off mid-document. Not retried: 404
(D49 reads it as a withdrawal), any other 4xx, a parse error that is not truncation, and
context cancellation — which is checked FIRST, because it surfaces as a transport error
and would otherwise be retried three times per remaining document against a deadline
already passed.

**The truncated-body case was unreachable in the first version**, and that is worth keeping
rather than quietly fixing. The function returned on the HTTP status before looking at the
error, so a response cut off mid-document — which arrives as **200** with an unexpected
EOF from the decoder — was classified permanent. The test row that should have caught it
used status 0, which is not how the failure arrives. Found by reading the test back, not by
running it.

**Three attempts, not more.** The delta fetches up to 20,000 documents one at a time, so a
feed that has genuinely gone away must fail quickly rather than turn into a slow death: at
this backoff a total outage costs each document about a second and a half. The pauses are
short on purpose — this is for a connection closed mid-handshake, not for a service under
load, and an assay build is one client.

---

### D59 — A scan can refuse vulnerability data that is too old

**Decision.** `--db-max-age=<duration>` exits 2 when the vulnerability data is older than
the duration. Off by default.

**Freshness is the upstream data's, not the build's** — which is D12, and it is the only
reason this can be honest. A mirror serving a six-month-old snapshot fetched an hour ago has
a recent `BuiltAt` and an ancient `DataAsOf`, and judging by the former would call it fresh.
D12 stored the two separately from the start for exactly this.

**The age is the OLDEST provider's.** A database is only as fresh as its stalest source, and
taking the newest would let one daily provider vouch for another that stopped updating in
March. The error names which one, because "the data is old" leaves the reader to work out
which feed died.

**An unknown age is refused, not passed.** This is D17's discipline applied to time: a
provider that could not say when its data was current has not said it is fresh. Treating
silence as "recent enough" would let through exactly the database this exists to catch —
the provider whose feed died is also the one least likely to report a date.

**Ratings and enrichment are deliberately not considered.** Both are additive. Stale NVD
means some findings carry no score, which the report already says (D17); stale KISA prose is
display copy that cannot move a verdict (D3). Only the ADVISORIES decide whether a package is
reported affected, so only their age can make a clean result untrustworthy — and folding
the others in would fail builds over prose.

**Exit 2, not 1** (D11). Out-of-date data does not mean "found nothing", it means the result
cannot be trusted, which is the same reason a schema mismatch exits 2.

**No default, and zero is not accepted from the command line.** The right number depends on
how the caller runs `db update`, and inventing one here would be a policy nobody chose.
Zero disables the check internally, so accepting `--db-max-age=0` would make a strict-looking
flag mean the opposite.

**The boundary is inclusive.** `--db-max-age=24h` against a database refreshed every 24 hours
must not fail half the time on a race with the clock.

---

### D60 — A bootstrap compares against the previous schema, not against nothing

**Decision.** When `db push` finds no artifact at the tag it is publishing to, it compares
against the previous schema's tag rather than skipping every coverage check.

**The hole was structural, not a slip.** `refuseCoverageRegression` compares against the
artifact at the *same* tag. A schema bump moves the tag, so the first push to `:vN` faced no
baseline at all — and every check was skipped at exactly the moment a hand-built bootstrap is
most likely to be missing something.

**It cost 352,000 ratings.** The `:v8` bootstrap after D52 was built locally with
`NVD_ENABLE` unset and published 3,081 NVD ratings where `:v7` held 355,030. Nothing
objected, because `:v8` did not exist yet. The daily job then fetches an *incremental* NVD
window — the API caps any range at 120 days — so a rating for a CVE last modified in 2023 is
never re-requested and the gap does not close on its own.

**The previous schema is the right baseline** because it holds the same corpus one shape
earlier, which is exactly what a bootstrap must not fall below.

**Schema 1 reports that it has no predecessor** rather than constructing `:v0`, a tag nothing
has ever published — a 404 dressed as a comparison would restore the same silent skip under a
different name. A repository with nothing published at all still accepts a first push, or the
tool could never ship one.

---

### D61 — A lockfile assay cannot read fails the scan

**Decision.** `yarn.lock` (v1) and `Pipfile.lock` are read; `npm-shrinkwrap.json` routes to
the `package-lock.json` parser. `pnpm-lock.yaml`, `uv.lock` and yarn berry lockfiles are
recognized, named, and **exit 2**.

**Recognition is the substance, not the parsers.** Before this, a repository whose only
lockfile was `pnpm-lock.yaml` scanned to completion, found nothing, and exited 0 — with
nothing in the report saying a lockfile had been passed over. "Found nothing" and "did not
look" arriving as the same verdict is the failure this project exists to prevent, and it was
sitting in the cataloger the whole time.

**Exit 2, and this is where it differs from `requirements.txt`** (D26). That file goes unread
because the FILE cannot answer the question — it carries ranges, not resolved versions, and
no tool could do better; the limit is documented and the scan is still trustworthy. These
files answer it perfectly and *assay* cannot read them, so a scan whose only manifest is one
of them has looked at none of the tree's dependencies. D11 puts 2 above both 1 and 0 for
exactly that.

**Yarn berry is detected rather than attempted.** Berry (v2+) is YAML under the same filename
as v1, and the v1 parser does not fail on it — it succeeds and finds nothing, because berry
writes `version: 1.3.0` where v1 writes `version "1.3.0"`. A clean verdict over an unread
lockfile is the worst of the available outcomes, so the format is sniffed (`__metadata:`, with
the `# yarn lockfile v1` banner settling it the other way) and refused.

**An aliased dependency resolves to the package installed, not the local name.**
`"aliased@npm:lodash@^4.0.0"` is lodash on disk and in every advisory; splitting on the last
`@` alone yields `aliased@npm:lodash`, a name no ecosystem has — a false negative, silent.

**pnpm and uv are deferred on a dependency, not on effort.** Neither YAML nor TOML is in the
standard library, and this project has two direct dependencies on purpose. Taking a third is a
decision (see `docs/deferred-decisions.md`), and until it is made, saying so loudly beats
guessing.

**Correction, measured and then fixed the same day (D62, D63).** The claim above is right about
pnpm and was wrong about uv. `uv.lock` is a flat sequence of `[[package]]` blocks whose name and
version are bare quoted scalars — the same subset `poetry.lock` has always been read with — so it
needs no TOML library. It is read as of D63. Only pnpm and yarn berry are still refused, and only
those two are a dependency question.

---

### D62 — crates.io, and the first ecosystem whose key is not its purl type

**Decision.** `Cargo.lock` is read, the OSV `crates.io` archive is ingested, and the ecosystem
key is `crates.io` while the purl type stays `cargo`.

**The two strings differ, and that is the hazard.** Every ecosystem before this one had a purl
type that either matched its key (`npm`) or differed by case (`pypi`/`PyPI`, `golang`/`Go`).
Rust is the first where they are unrelated words. Writing `cargo` as the ecosystem sends every
lookup to a bucket no provider ever writes, and a lookup that finds nothing reports **clean** —
so this is asserted on the package the cataloger produces, not left to the store.

**The archive is small and unusually well rated.** Measured 2026-08-13: 2,725 records, 3.4 MB
against npm's 203 MB. 1,518 GHSA, 1,197 RUSTSEC, 10 `MAL-*` (excluded, D15), 87 withdrawn
(dropped at ingestion, D16). **62% carry a severity**, against roughly half across OSV as a
whole — RUSTSEC rates its own advisories. 3,657 ranges are `SEMVER` and 190 `ECOSYSTEM`.

**Cargo's versions are semver, so the comparer is the one npm and Go already use.** Cargo
refuses to publish a crate whose version is not semver-compliant and `Cargo.lock` records the
resolved one, so there was nothing per-ecosystem to write. This is the first time D9's answer
was "the existing comparer, unchanged", and it is worth naming as such: the rule is that
version schemes get their own comparer *when they disagree*, not that every ecosystem gets one.

**A local crate is cataloged, not skipped.** The root crate and any path dependency carry no
`source` field. They are still components of the tree, and skipping them would put "not
evaluated" above zero on every healthy Rust scan — the defect `npmlock` hit with
`package-lock.json`'s root key, which made `--fail-on-incomplete` exit 2 where nothing was
wrong.

**A table header closes the block.** `Cargo.lock` v1 ends with a `[metadata]` table whose keys
name every package again. Reading past it lets a stray assignment complete a block whose own
version never arrived. Together with first-assignment-wins these are two guards on one hazard,
and they only differ on an incomplete block — which is what the test for the header rule uses,
because with both fields set the other guard makes the mutation invisible.

**Until the published database is rebuilt, a Rust scan exits 2 rather than reporting clean.**
`store.Covers()` already refuses an ecosystem the database does not hold, so the cataloger
could land before the data without a silent verdict. That ordering is safe by construction, not
by care.

---

### D63 — uv.lock, and the reader three lockfiles now share

**Decision.** `uv.lock` is read. The block scanner behind `Cargo.lock` moves into
`internal/cataloger/tomlblock` and both catalogers use it.

**This is a correction, not a feature.** D61 refused `uv.lock` on the grounds that it needs a
TOML library. That was reasoning from the format's *name* rather than from the file, and it was
wrong for eight hours: measured against `astral-sh/uv`'s own 1,650-line lockfile, the scanner
written for `Cargo.lock` reads **77 of 77 `[[package]]` blocks with none skipped**. Scanning the
real repository now finds 23 findings across all 77 packages, none of them not-evaluated.

**Worth recording as a failure mode, because it is cheap to repeat.** A deferred entry that
names a wrong constraint is worse than one that names none: "needs a third dependency" reads as
settled and stops anyone looking, where "nobody has written it" invites the twenty minutes it
actually took. The measurement that corrected it was one `curl` and one simulation of the
scanner in a throwaway script.

**The subset is the real boundary, not the format.** `Cargo.lock`, `uv.lock` and `poetry.lock`
are all TOML, and all three are machine-written as a flat sequence of `[[package]]` tables whose
name and version are bare quoted scalars. Anything outside that subset yields **no field** here
rather than a wrong one — `source = { registry = "..." }` and `wheels = [` are simply not quoted
scalars — so the reader degrades into a counted skip instead of a fabricated version. pnpm's
YAML has no such property: its nesting means a restricted reader parses fixtures and mis-reads
real files, which is why D61's refusal stands there.

**One scanner, not two copies.** The catalogers differ only in ecosystem, purl type and package
type. Duplicating the scanner would mean a fix to one reader silently not reaching the other,
and the defect that produces — a package that is never cataloged — is a false negative.

**uv needs no database rebuild**, unlike crates.io: PyPI has been ingested since slice 1, so
these findings work the moment the binary ships.

---

### D64 — The Red Hat archive is spooled to disk before it is parsed

**Decision.** `Fetch` downloads the 261 MB archive to a temporary file, closes the connection,
then decompresses and parses from disk. The download retries with `Range` resume, and a
transfer that ends short of the promised length is an error rather than a short archive.

**This is the 2026-08-13 publish failure.** The build died at 1h3m with
`read csaf_vex_2026-08-09.tar.zst: read tcp ...: connection reset by peer`, and produced no
artifact that day.

**D56's instrumentation named the cause in the same output that reported the failure:**

```
provider  Red Hat CSAF VEX   10m23s  0 record(s) [2m4s fetch, 8m19s store] (failed)
```

Two minutes of transfer, eight of storing, one connection held open across both. Streaming the
archive while writing every record it produced kept the socket alive four times longer than the
download needed it, and the reset arrived in the extra time. Spooling first is not an
optimization — it removes the window rather than surviving it.

**D58's retry did not help, and that is the lesson worth keeping.** It was written the day
before for exactly this class of failure, and it covers the *delta documents*: a different code
path, reached after the archive. The retry was real and the reasoning was right; it was simply
attached to the half that was not failing. A transient-failure fix should name which transfers
it covers, because "we added retries" reads as covering all of them.

**Resumed, not restarted.** The server supports `Range`, so an interruption at 200 MB costs the
remaining 61 MB. A server that ignores `Range` answers 200 with the whole file, and that case
truncates the spool first — appending would produce one and a third copies of the archive, which
zstd rejects minutes later and nowhere near the cause.

**A short download is an error.** zstd and tar both stop at a truncation without complaining, so
a build would otherwise publish an artifact missing whatever was in the tail and say nothing.
`net/http` enforces `Content-Length` itself, so the only way a short body arrives with no error
is a chunked response — which a proxy in front of the archive can produce, and which the test
for this has to construct deliberately.

---

### D65 — The NVD window gets an end, so the backfill can be sliced

**Decision.** `NVD_UNTIL_DAYS` bounds the late end of the NVD window; `Provenance` records
`CoversUntil` beside `CoversSince`; and a seeded build's merged coverage only reaches further
back when the slice's window **touches** the range already covered.

**The problem it exists for.** The 352,000 lost ratings (D60's incident) cannot come back on
their own, and they cannot come back in one run either: every window before this ended at
"now", so `NVD_SINCE_DAYS=120` and `=365` cost the same near-full pass — NVD keeps touching
records, so 120 days of *modifications* is most of the feed. The unbounded pass is about
seven hours with **no resume point**: `db build` installs its temporary database only at the
end, so a failure at hour five discards five hours. Four attempts died exactly that way
before the README said to stop trying.

**The artifact is the checkpoint.** With an end on the window, the backfill becomes closed
slices walked backwards — `[now−240d, now−120d]`, `[now−360d, now−240d]`, … — each run
seeding from the published artifact and publishing in turn. A failed slice costs one slice.
No new checkpoint format, no resumable build: the mechanism that already carries ratings
forward nightly (`mergeRatingCoverage`, D-seeded builds) carries the backfill too.

**The honesty rule is the substance.** A slice's ratings always land in the database — they
are real whatever order the slices run in. The **claim** is what the touch rule bounds:
coverage only extends backwards when the slice's end reaches the seed's start, so running
slices out of order leaves the claim where it was rather than asserting a span with a hole in
it. A database claiming a year while holding four months of it is exactly the over-claim D20
exists to prevent, and the merge's default (`merged := fetched`) would have produced it —
both branches are written out because falling through *was* the bug.

**On a gap, the merged end is the seed's, not the slice's.** Leaving the slice's end in place
would say the artifact covers nothing since April — false in the direction that matters,
because tomorrow's nightly would look like it was widening coverage and the publish guard
would wave a narrower artifact through.

**The 120-day cap is on the window's width, not its start** — corrected after the first
slice ran. The pre-D65 cap applied to `NVD_SINCE_DAYS` alone, which was the same thing while
the end was always "now" and made every deeper slice unrepresentable afterwards: the first
dispatch of `[240,120]` had SINCE capped to 120, which made UNTIL=120 read as inverted, and
the two warnings composed into a `[120, now]` window nobody asked for. It happened to be the
most useful window in the feed and recovered the ratings corpus in one 51-minute run — luck,
not design, and the guards' own honesty (both warned, `db status` disclosed the real window)
is what made the accident visible. A too-wide slice now clamps to 120 days above its own end
and says so.

**An end with no start is ignored.** `NVD_UNTIL_DAYS` without `NVD_SINCE_DAYS` is a window
from 1999 to a date in the past — the seven-hour pass with extra steps, requested by someone
reaching for a bounded slice. An inverted window (end at or before start) is refused with a
warning rather than sent to NVD, which answers it with a bare 404 an hour in.

**What it deliberately does not do.** The API key stays optional and nearly irrelevant here:
the rate-limit pause is 20 minutes of a seven-hour unbounded pass — the time is NVD serving
2,000-record pages, and no key changes that. And each backfill slice still rebuilds OSV and
Red Hat (~77 minutes) today; a ratings-only build mode is the next slice, not this one.

---

### D66 — A build that re-rates without re-fetching

**Decision.** `db build --ratings-only --seed <ref>` carries the seed's advisories verbatim —
a file copy, not a record copy — and runs only the rating annotators on top. The advisory
providers do not run.

**It exists to make D65's slices affordable.** A backfill slice needs the NVD window and
nothing else, but every build rebuilt OSV (~54 minutes, almost all of it store) and Red Hat
(~21 minutes) regardless — 75 minutes per slice of work whose output is identical to the
seed's. Three slices would have spent nearly four hours rebuilding the same advisories three
times inside a 2-hour job cap.

**The advisories' provenance is carried too**, because it is true: this build did not fetch
them, so their `DataAsOf` is the seed's, and `db status` says so. A ratings-only publish
therefore never claims fresher advisory data than it has — the freshness that regressed is
the freshness that was already published.

**Two refusals, both the D60 class.** Without a seed there are no advisories at all, and an
empty-advisory database published over a real one is the bootstrap incident again. Without an
annotator enabled the build would change nothing, and "changed nothing" arriving as success
trains the operator to trust a no-op.

**The withdrawal caveat is the cost, and it is bounded by the nightly.** A full build drops
advisories withdrawn upstream since the last run (D16 at ingestion); a ratings-only build
carries them, because it does not consult the providers at all. Acceptable when the seed is at
most a day old — the next nightly rebuild sweeps them — and wrong for anything older, which is
why the flag's own usage text says so rather than leaving it to this document.

---

### D67 — One index key per (package, advisory)

**Decision.** The `advisories` index maps `<eco> <name> <advisoryID>` to nothing,
one key per pair, replacing per-package JSON arrays of IDs. Schema 8 → 9.

**Why.** Measured three times: the OSV stage spends ~47–54 minutes storing against ~1.5
fetching, after D57's batching. The cost was `appendID`'s read-modify-write — every insert
re-read, unmarshalled, scanned and re-wrote its package's whole ID list, quadratic on hot
packages. A composite key is one blind `Put`: no read, no marshal, dedup free because a
re-Put lands on the same key.

**Lookups walk a cursor from `Seek(prefix)`, and the prefix ENDS with the separator** —
without it `openssl` prefix-matches `openssl-foo`, the substring-collision class CLAUDE.md
documents, moved into the key space. The prefix is built in exactly one function shared by
every writer and the scan, so they cannot disagree.

**The bootstrap does not repeat the v8 incident.** `OpenSeedRatings` reads schema N−1 for
the RATINGS bucket alone (its shape did not change); the ratings-only path refuses an old
seed entirely, because it carries advisories verbatim and the advisories are what changed.
D60's guard compares the first `:v9` push against `:v8`, so 357,678 ratings is the floor a
bootstrap must carry.

---

### D68 — Four language ecosystems, and the comparers that carry them

**Decision.** Maven, RubyGems, NuGet and Packagist are ingested from OSV and matched with
per-ecosystem comparers ported from each ecosystem's canonical implementation: Maven's
ComparableVersion (3.9.x — the line GHSA ranges were authored against, not Maven 4),
rubygems' Gem::Version, NuGet.Versioning's VersionComparer.Default, and composer's
VersionParser over PHP's version_compare.

**Measured before built** (2026-08-18): 6,948 / 4,656 / 1,877 / 6,938 records; RubyGems is
75% MAL-* (excluded, D15) so its real corpus is ~1,078; ranges are almost entirely
ECOSYSTEM-typed, so the comparers carry the whole matching burden — which is why each was
specified by research against the canonical source, oracle-validated (composer 98/98 against
its own test data; Maven replaying its entire ~600-assertion suite), and implemented in the
main loop per D9's delegation rule. All four tables passed on first run.

**The Drupal fold.** The Packagist archive carries 521 records keyed
"Packagist:https://packages.drupal.org/8" — Drupal contrib advisories, all drupal/* names
with pkg:composer purls. They are ingested with the key REWRITTEN to plain "Packagist":
no lookup can ever construct the qualified key, so preserving it stores unreachable data,
and the drupal vendor is reserved on packagist.org so the fold cannot collide. Packagist
only — a distro's release qualifier (Alpine:v3.19) is part of its key by design (D6), and
the fold's own test pins that it must NOT generalize.

**Name plumbing the purls forced.** Maven's OSV names are group:artifact (12,457 of 12,457
measured) while its purls are pkg:maven/group/artifact, so the CycloneDX namespace join is
":" for maven and "/" for everything else. NuGet package IDs are case-insensitive (98%
of advisory names are mixed-case), so NormalizeName lowercases NuGet — one definition,
shared by store and matcher, as always.

**Recorded divergences from the canonical implementations**, all in the refusing direction:
an empty version errors everywhere (rubygems reads it as 0, Maven as equal-to-0 — both
would mark a package clean on corrupt input); NuGet's internal-whitespace tolerance
("1. 2 .3") is rejected; Maven digits are ASCII-only (Maven 4's rule; 3.x accepts Unicode
digits via Character.isDigit). Faithful oddities kept: NuGet's int32 label overflow falls
back to string comparison, composer's patch > stable and uppercase-STABLE-below-dev, and
Maven's BigInteger-zero outranking int zero.

**Verified end to end** on a seven-probe SBOM: log4shell at critical 10.0 through the Maven
namespace join, Spring's .RELEASE alias resolving in a live lookup, Newtonsoft.Json through
the NuGet case fold, DRUPAL-CONTRIB-2017-082 through the Packagist fold, and nokogiri's
1.13.0.rc1 caught inside its vulnerable range through Gem prerelease ordering. SBOM scans
work today; lockfile catalogers (Gemfile.lock, composer.lock, packages.lock.json) are the
next slice.

---

### D69 — Lockfile catalogers for the D68 ecosystems

**Decision.** A directory scan reads `Gemfile.lock`, `composer.lock` and `packages.lock.json`,
completing the path D68 opened: the ecosystems matched from SBOMs now match from checkouts.
Maven deliberately has no entry here — it has no lockfile; its path is jar scanning, still
deferred.

**Gemfile.lock is indentation-sensitive and the indentation is the parser.** In the `GEM`
section's `specs:` block, a 4-space line is an installed package and a 6-space line is that
package's dependency CONSTRAINT (`actionpack (= 7.0.4)`) — cataloging the 6-space lines
would invent packages at versions nothing installed. The distinction is pinned by its own
test. `GIT` and `PATH` specs are counted and skipped, not cataloged: their source is not
rubygems.org, and a fork at version X need not carry the fix that rubygems' X carries —
the same treatment Pipfile's VCS entries get, for the same reason.

**composer.lock keeps versions verbatim, `v` prefix and all.** The Composer comparer owns
normalization; a cataloger that stripped the prefix would be a second definition of that
rule, one drift away from disagreeing with it. `dev-*` versions are counted and skipped —
the comparer refuses branches by design, and the skip is the honest surface for that
refusal. Both `packages` and `packages-dev` are read: a dev dependency is still installed
in CI, which is where a scan runs.

**packages.lock.json walks every framework and dedupes on (name, resolved).** One package
restored for net6.0 and net8.0 is one component, not two. `"type": "Project"` entries are
project references with no resolved version — counted, skipped, never guessed at. Names
keep their case verbatim; `NormalizeName` lowercases NuGet at match time, in the one
definition store and matcher share.

**What this does not change.** The exit-2 contract for recognized-but-unreadable formats
(D61) is untouched: pnpm and yarn berry still refuse. And the counted-skip invariant —
Components == Cataloged + skips, held by every cataloger since slice ⑥ — is asserted for
each of the three by the caller-first tests, before the parsers' own.

---

### D70 — Jar scanning: identity from pom.properties, never from the filename

**Decision.** `assay scan app.jar` (and every `*.jar`/`*.war` a directory scan finds) reads
Maven identity from `META-INF/maven/<group>/<artifact>/pom.properties` entries — every one of
them, recursing into nested archives to depth 3 with a 512 MiB per-entry cap. A jar with no
pom.properties is a counted, disclosed skip. Nothing is ever guessed from the filename or
MANIFEST.MF.

**The refusal to guess is the decision.** `foo-1.2.3.jar` names a file, not a package: a
fabricated GAV is wrong in both directions — a false positive against coordinates nobody
ships, or a false negative clearing coordinates they do. Other scanners take the filename
heuristic; assay takes the loud skip, and the summary line ("2 components seen, 1 evaluated,
1 not evaluated") is that refusal made visible.

**Every pom.properties in an archive is a component.** A shaded jar embeds its dependencies'
entries, and surfacing all of them is the only way a shaded log4j is caught. A nested jar
with no identity of its own still recurses — an anonymous shell around identified contents
is the ordinary Spring Boot shape (`BOOT-INF/lib/*.jar` needs no special casing; it is just
a zip entry ending in .jar).

**The caps refuse loudly.** Depth past 3 and entries past 512 MiB are counted skips, never
silent truncation — a zip-bomb guard that quietly dropped the tail would read as coverage.

**Verified end to end**: a synthetic fat jar — anonymous outer, log4j-core 2.14.1's
pom.properties nested under BOOT-INF/lib — reports log4shell at critical 10.0 with the outer
shell counted as not evaluated. This closes the Maven checkout path D69 could not (Maven has
no lockfile): SBOM, jar and fat jar all match now.

**Deferred, recorded**: jars inside container images need a whole-tree walk the Source
interface does not expose yet — the image path still catalogs OS packages only.

---

### D71 — Rocky Linux, and the five decisions the RPM-family research fixed

**Decision.** Rocky Linux 8/9/10 are ingested from OSV's `Rocky Linux` archive (measured
2026-08-19: 3,941 records, 84.1% carrying CVSS v3 vectors, CVE linkage via `upstream` at
99.3%) under release-qualified keys `Rocky Linux:<major>`; an os-release `ID=rocky` routes
there, and the existing RPM comparer applies. Rocky leaves D50's not-evaluated list; Alma,
Fedora and the rest stay on it until their own slices land.

**The research fixed five decisions at once, recorded here because the next four slices
reuse them:**

1. **`related` joins the CVE read (D3 revised), scoped to distro-authored records.** Alma
   keeps its CVEs ONLY in `related` — under D3 as written it would ship with zero ratings,
   silently. The scope stays narrow because `related` on GHSA records carries genuinely
   related-but-different advisories, and a global read would fabricate alias joins.
   Implemented with the Alma slice, which cannot ship without it; Rocky does not need it.
2. **A feed without CVSS stores its vendor severity word losslessly AND joins NVD** — both,
   not either: the word is what the vendor asserted (D13: store upstream, derive at query
   time), the NVD join is what D25 aggregates. Alma/Amazon/Fedora need this; Rocky mostly
   does not (84% native vectors).
3. **Module builds are dropped and counted (D47's answer), not stream-matched.** Rocky 8 is
   86% module entries, 9 is 28%, 10 is 0% — so Rocky 8's coverage through this provider is
   thin and the skip counts say so on every scan. Reading rpmdb's MODULARITYLABEL and
   matching stream-qualified is its own future slice; until then the loud skip beats a
   stream-blind match that would be wrong in both directions.
4. **OSV is the primary feed where it exists.** Confirmed against the alternatives by
   measurement: Alma's own errata API is missing 38% of release-10 records the OSV export
   carries; Rocky's Apollo API adds module metadata but no coverage. Enrichment later,
   primary never.
5. **SLES stays deferred behind the ndb rpmdb backend** — and the research removed the
   recorded justification for deferring ndb itself (modern SLES/BCI images cannot even be
   cataloged today). openSUSE Leap is the clean subset if SUSE-family value is wanted first.

**The hazard this ships with, disclosed rather than hidden:** Rocky's feed has measured
coverage holes — no advisory for regreSSHion at all, and 2023–24 output running 41–57% of
RHSA's. A Rocky scan's "clean" is clean-of-what-Rocky-published, a weaker statement than the
RHEL verdict, and — like every feed this research measured — errata-only, so
`--fail-on-unfixable` has nothing to gate on. The README's Rocky line says both.

---

### D72 — AlmaLinux, spending the two D71 decisions it could not ship without

**Decision.** AlmaLinux 8/9/10 are ingested from OSV's `AlmaLinux` archive (measured
2026-08-19: 5,606 records — 4,405 ALSA (security), 979 ALBA (bugfix), 222 ALEA (enhancement),
1 withdrawn) under release-qualified keys `AlmaLinux:<major>`; an os-release `ID=almalinux`
routes there, and the existing RPM comparer applies. AlmaLinux leaves D50's not-evaluated
list, the second (and so far only other) distro to do so after Rocky in D71.

**Where D71's research paid off directly.** Two of the five decisions D71 recorded were
written FOR this slice, not for Rocky, which needed neither:

1. **`related` joins the CVE read (D3 revised).** AlmaLinux's archive carries zero `aliases`
   and zero `upstream` on every one of its 5,606 records — the CVE lives ONLY in `related`.
   Implemented scoped to distro-authored records (`osv.distroAuthored`): ALPINE, DEBIAN,
   UBUNTU, RLSA (Rocky) and AlmaLinux's own ALSA/ALBA/ALEA qualify; GHSA, RUSTSEC and every
   other language-ecosystem namespace do not, because their `related` names genuinely
   different, merely similar advisories, and a global read would fabricate an alias join
   between two distinct vulnerabilities.
2. **Vendor severity words, stored losslessly (D13).** 0% of the archive carries a CVSS
   vector anywhere — severity exists only as the summary's leading word ("Important: openssh
   security update", following Critical/Important/Moderate/Low, the RHSA convention Alma
   inherits byte-for-byte). Stored as a `VENDOR_WORD` severity entry at ingestion and banded
   by `internal/severity` at query time (D13's usual split), never banded at ingestion.
   Critical→critical, Important→high, Moderate→medium, Low→low; an unrecognized word bands
   Unknown rather than a guessed default (D17).

**ALBA and ALEA are dropped at ingestion, not stored and filtered later.** Bugfix and
enhancement errata name no vulnerability at all — a different reason from `MAL-*` (D15),
which IS a security finding, only of a different class. Mirrors the withdrawn/`MAL-*`
pattern: dropped in `osv.Convert`, so no query path can forget the check (D16).

**The module-build guard needed no new code, only a wider key.** D71's guard
(`internal/matcher`'s `moduleBuildBound`) is gated on the RPM comparer, not on any ecosystem
string, and already recognized both spellings — Red Hat/Rocky's `module+el` and AlmaLinux's
own `module_el` — because `rpmModuleBuild` was written against both from the start. Routing
`AlmaLinux:N` to `version.RPM{}` was the only change the guard needed; it is proven by a
caller-first test (an Alma module-build fix reaches the same skip-and-count path), not by new
production code.

**Disclosed rather than hidden:** an AlmaLinux verdict carries Rocky's errata-only caveat
(measured against the same OSV pipeline) plus a shape of its own — every severity is a vendor
word rather than a score, and unlike Rocky's 84.1% native CVSS coverage, AlmaLinux has none at
all. The README's AlmaLinux line says so next to the feature.

---

### D73 — Amazon Linux, the first updateinfo provider

**Decision.** Amazon Linux 2 and 2023 are ingested from their own repos' `updateinfo.xml`
(repomd indirection followed live — the final URLs carry rotating hashes), keys
`Amazon Linux:2` / `Amazon Linux:2023`; `ID=amzn` routes on VERSION_ID, and AL1
("2018.03") and AL2022 stay not-evaluated with the version named. `AMAZON_ENABLE` is on
by default, like Red Hat: the published artifact should carry it.

**D71/D72's decisions applied unchanged**: CVE references land in `Related`
(distro-authored), severity is a VENDOR_WORD stored losslessly and banded at query time.
Two facts the feeds forced: Amazon spells the middle band **Medium** (never RHSA's
Moderate — both words now map), and AL2 writes the words lowercase while AL2023
capitalizes them, so the provider canonicalizes case before storing (the severity map
stays deliberately case-sensitive; normalization is the provider's job, verified by
mutation both ways).

**Core-only is a known partial view, disclosed** (the one new decision): AL2's 73 extras
repos (964 advisories — docker, ecs, kernel livepatches) are not fetched. Fetch prints
one line saying so, and the usage text carries the same sentence. Extras become their own
decision when someone scans an image that uses them.

**No modularity in Amazon's release strings** — the RPM module-build guard is inert here
by construction, noted in the package doc rather than tested against nothing.

---

### D74 — Oracle Linux, and the first OVAL parser

**Decision.** Oracle Linux 5–10 are ingested from Oracle's ELSA OVAL feed
(com.oracle.elsa-all.xml.bz2, spooled per D64, streamed through stdlib bzip2+xml): the
criteria tree (AND/OR over rpminfo tests) is walked per major, one Advisory per
(ELSA, major) under keys `Oracle Linux:<major>`. `ID=ol` routes; `ORACLE_ENABLE` on by
default. 9,796 definitions, the richest severity data of the family: CVSS v3 vectors parsed
natively, the vendor word stored beside them (D71 decision 2, both arms).

**The v2 decision.** 8.8k pre-2016 definitions carry CVSS v2 only. A v2 parser was
considered and rejected: their band comes from the NVD join via the CVE in `Related` —
the same fallback arm decision 2 already names, and one less scoring implementation to
keep faithful.

**The UEK guard is cross-definition, corrected from the design.** The brief assumed the
multi-train ambiguity lives inside one definition's criteria; measured against the real
archive it does not — three separate ELSAs fix the same CVE's `kernel-uek` at three
different EVRs for one major. The guard therefore indexes (CVE, major, package) across the
whole corpus and drops-and-counts collisions: matching a version against the wrong kernel
train is wrong in both directions, and 857 OL8 / 817 OL9 groups collide. Module-stream
conflicts fall out of the same guard for free.

**Disclosed, not fixed here:** ksplice- and FIPS-lineage packages are not filtered — the
Ubuntu-D53-shaped hazard, recorded in the package doc and this entry as the follow-up
decision Oracle still owes.

---

### D75 — Fedora, shipped with its hazards counted

**Decision.** Fedora's current releases are ingested from Bodhi's REST API (security
updates, `FEDORA-` ids only so EPEL cannot fold in) under keys `Fedora:<release>`;
`ID=fedora` routes; `FEDORA_ENABLE` on by default. The research ranked Fedora last on
value-per-effort, and the answer is not to skip it but to ship every weakness loud:

1. **The API is slow and bot-fronted** — sequential pagination, descriptive User-Agent,
   retries only on 429/5xx with cancellation checked first (D58's classification order).
2. **CVEs come from prose** — regex over title+notes, measured ceiling 81.7%. Every update
   with no extractable CVE is COUNTED and the build log says so; the miss is never silent.
3. **The 13-month EOL freeze** — an EOL'd release gets no new advisories, so its lower
   bound silently freezes. Fetch names which releases were fetched and says exactly that;
   the usage text repeats it. The scan side cannot know a release went EOL, so the
   disclosure lives where the knowledge does.

Bodhi's severity ladder (urgent/high/medium/low/unspecified, measured lowercase) maps
faithfully as its own VENDOR_WORD entries — Urgent→critical, High→high, the shared
Medium/Low, and `unspecified` deliberately unrecognized: it is Bodhi's own "nobody set
one", which is Unknown, never a defaulted Low (D17). 0% CVSS in the feed; the NVD join
carries the rest (D71 decision 2).

This closes the buildable RPM family: Rocky, Alma, Amazon, Oracle, Fedora (D71–D75).
SLES remained behind the ndb rpmdb backend until D76.

---

### D76 — The ndb rpmdb backend: cataloging only, SLES's own advisory feed still open

**Decision.** `internal/cataloger/rpmdb/ndb.go` reads rpm's third on-disk container format —
openSUSE's and SLES's own, `/usr/lib/sysimage/rpm/Packages.db` — and feeds the same
format-agnostic header parser (`header.go`) the BerkeleyDB and SQLite backends already share
(D44). `scancmd.go`'s RPM routing switch, which used to refuse an `ndb` database BY NAME
(`"...which this build does not read; there is no SUSE advisory source for it to serve"`),
now reads it exactly like the other two. This is cataloging only: `pkgmeta.Distro.Ecosystem()`
still has no key for `sles` or `opensuse-*` (D50 routes only `rhel`), so an ndb image's
packages are catalogued unkeyed, and the matcher reports them not evaluated — the same shape
D43 gives every unrouted RPM family. A SUSE advisory provider is the next slice, not this one.

**Why now.** D44 deferred ndb with two reasons bundled into one sentence: "openSUSE/SLES
only, no Red Hat lineage uses it, and there is no SUSE advisory provider for it to serve."
`docs/deferred-decisions.md`'s SLES research (feeding D71–D75, measured 2026-08-19) split
that sentence and found only the second half still true: modern SLES/BCI images could not be
**catalogued at all**, independent of any advisory question. That half of the justification is
what this closes; the advisory half is exactly as open as it was.

**The format, verified against the source, not the sketch that opened this slice.** Every
on-disk fact came from `rpm-software-management/rpm@master`,
`lib/backend/ndb/rpmpkg.c` (`rpmpkgReadHeader`, `rpmpkgReadSlots`, `rpmpkgReadBlob`,
`rpmpkgWriteBlob`), then checked against a REAL `registry.suse.com/bci/bci-base:latest`
`Packages.db` pulled with a throwaway `go-containerregistry` program (not committed — see
below). Two things the opening sketch had only approximately right:

- **Every integer is little-endian, unconditionally.** Unlike BerkeleyDB (`bdb.go`), which
  writes host order and uses its magic as a byte-order probe because s390x is a supported RHEL
  platform, ndb's own source has no such probe anywhere — it was written once, for x86, and
  the format never grew one.
- **A block is 16 bytes**, confirmed both in `rpmpkg.c`'s `BLK_SIZE` and by recomputing a real
  blob's block count from its stored length and getting the slot's own `blkcnt` back exactly.

The full layout: a 32-byte header (`RpmP` magic, version, generation, `slotnpages`,
`nextpkgidx`, all little-endian `uint32`) occupies the byte range of the slot table's first two
entries; the slot table proper is `slotnpages × 4096` bytes of 16-byte slots (`Slot` magic,
pkgidx, block offset, block count), stamped with the magic on every slot — occupied or not —
so a missing magic anywhere means the table itself is damaged; a deleted or never-allocated
slot has the magic but a zero block offset, nothing else; each occupied slot's blob starts with
a 16-byte head (`BlbS` magic, pkgidx, the database's own generation counter, byte length), the raw rpm header
(the same bytes `parseHeader` already reads out of the other two backends), zero padding to a
whole number of blocks, and a 12-byte tail (adler32 checksum, byte length again, `BlbE` magic).
rpm's own reader skips the adler32 check on an ordinary read and verifies it only when
explicitly asked; this reader always verifies — the cost is one pass over bytes already being
read, and D45's SQLite/BerkeleyDB backends both do full structural validation before trusting
anything, for the same reason.

**Corruption is split the same way the other two backends split it (D45).** A damaged slot
table — a slot without its magic — fails the WHOLE read: the table is what makes every
pkgidx/block-offset pair trustworthy, so once it is suspect nothing downstream can be either. A
damaged individual blob — wrong magic, a length mismatch, an adler32 mismatch, a pkgidx beyond
what the header's own `nextpkgidx` says was ever allocated, two slots claiming the same pkgidx —
is a counted, per-package skip, the same way one unreadable header blob is on the BerkeleyDB and
SQLite paths. A truncated file is refused at both the slot-table and the per-blob level. None of
this is theoretical: mutation-tested by deleting each guard in turn and confirming the relevant
test goes red (the deleted-slot skip, the slot-magic check, and the adler32 check each turn a
passing test red when removed), and the scancmd routing line was mutation-tested the same way —
removing the `case rpmFound.ndbPath != "":` arm turns both the cataloging test and the
end-to-end `Run` test red.

**Verified against the real file.** `registry.suse.com/bci/bci-base:latest`, pulled
2026-08-20, single layer, `Packages.db` 5,595,120 bytes, `slotnpages` 1, `nextpkgidx` 146 (145
package-index numbers ever allocated), 144 occupied slots. `ReadNDB` recovers **138 packages,
0 skipped, 0 corrupt** — the gap from 144 is 6 `gpg-pubkey` keyring entries this build filters
(D44's rule, reached from ndb through the shared header pipeline) and the one already-deleted
slot the header's own bookkeeping implies (145 allocated − 144 occupied), which is a real,
in-the-wild instance of the deleted-slot path the fixture tests exercise synthetically. Three
samples, byte for byte as read: `sles-release 15.7-150700.67.6.1` (source `sles-release`),
`rpm-ndb 4.14.3-150400.59.19.1` (source `rpm-ndb` — rpm's own ndb-aware tooling, installed on
the image whose database this slice now reads), `zypper 1.14.98-150700.13.6.1` (source
`zypper`). Every sampled package's `SOURCERPM` stripped correctly (D8), confirming the shared
header pipeline is genuinely reached, not reimplemented.

The pull program and the real `Packages.db` are not committed — a multi-MB binary is not a test
fixture (see `docs/deferred-decisions.md`'s note on this same tradeoff for the BerkeleyDB
fixture). The committed tests instead hand-build a ≤20 KB synthetic ndb file in Go, covering two
packages, one deleted slot, a corrupt slot-table magic, a truncated file, and a damaged blob
(adler32 mismatch) — both at `internal/cataloger/rpmdb` (`ndb_test.go`, sharing the package's
own `buildHeader` test helper) and, independently reimplemented from the same source facts
because it is a different package, at `internal/scancmd` (`rpm_test.go`, `buildNDBFixture`) for
an end-to-end `Run` test: an ndb-backed SLES image now scans to completion — one package
catalogued — and fails only because nothing keys `sles` to an ecosystem yet, not because the
database could not be opened at all.

**What is still open**, and belongs to a future slice, not this one: a SUSE advisory source
(there still is none — `docs/deferred-decisions.md`'s SLES entry is otherwise unchanged), and
therefore `pkgmeta.Distro.Ecosystem()` keys and `version.For` comparer routing for `sles` and
`opensuse-*`. This slice deliberately does not touch either.

---

## 3. Architecture

### Measured data volumes

Measured 2026-07-29 against the live OSV dumps. These numbers are what D4 (bbolt),
D15 (excluding `MAL-*`), and D17 (unknown severity) rest on — re-measure before revisiting
any of them.

| Ecosystem | Vulnerability records | Size | `MAL-*` records | Size |
|---|---:|---:|---:|---:|
| Go | 8,599 | 22.1 MB | 18 | 0.0 MB |
| npm | 7,004 | 19.2 MB | 216,865 | 323.2 MB |
| PyPI | 13,010 | 44.9 MB | 11,579 | 20.1 MB |
| **Slice 1 total** | **28,613** | **86.2 MB** | **228,462** | **343.3 MB** |

Sizes are uncompressed JSON. Compressed download for slice 1 is ~244 MB regardless of
filtering.

For later slices: Alpine 4,401 records (3.8 MB compressed), Debian 64 MB compressed,
Ubuntu 570 MB compressed. All 46 ecosystems total roughly 1.5 GB compressed.

At 28,613 advisories and 86 MB, bbolt with JSON values is comfortably within range. Even
the unfiltered 257,075 records at 430 MB would work — the decision has substantial headroom
either way.

**Red Hat data does exist in OSV** (25 MB compressed), contradicting an earlier assumption
that it was absent or negligible. Whether it is backport-aware enough for accurate RHEL
matching is a separate question, open until that work starts.

### Pipeline

```
target (image | binary | dir | SBOM file)
  │
  ├─▶ Source      open the target for file access; carries layer provenance
  ├─▶ Cataloger   files → []Package, one per ecosystem
  ├─▶ Target{Distro, []Package}          ◀── normalized inventory
  ├─▶ Matcher     Package × Store → Finding, using per-ecosystem Comparer
  ├─▶ Enricher    join KISA data by CVE ID
  └─▶ Reporter    table / JSON / SARIF, --fail-on
```

The database is orthogonal to this flow and read-only during a scan:

```
Provider(OSV)  ─┐
                ├─▶ []Advisory ─▶ Store          written only by `assay db update`
Provider(KISA) ─┘                    ▲
                                     └── Matcher reads
```

### Interfaces

| Interface | Responsibility | Implementations |
|---|---|---|
| `Source` | Open a target for file access | image, dir, file, binary |
| `Cataloger` | Files → `[]Package` | apk, dpkg, cyclonedx, go-mod, go-binary, npm, jar |
| `Store` | Advisory lookup | bbolt |
| `Comparer` | Version ordering within one ecosystem | semver, PEP 440, apk, deb, rpm |
| `Provider` | Upstream feed → `[]Advisory` | OSV, KISA |

Supporting a new ecosystem means writing one `Cataloger` and one `Comparer`. Nothing else
changes — that is the property the whole decomposition exists to provide.

```go
type Store interface {
    Lookup(ecosystem, name string) ([]Advisory, error)
    LookupBySource(ecosystem, sourceName string) ([]Advisory, error)  // D8
    Enrichment(id string) (*Enrichment, error)
    Meta() (Meta, error)
    Close() error
}

type Comparer interface {
    Compare(a, b string) (int, error)  // D9
}

type Provider interface {
    Fetch(ctx context.Context) ([]Advisory, Provenance, error)
}
```

### Core types

```go
type Target struct {
    Distro   *Distro    // from /etc/os-release; nil for language-only targets  (D7)
    Packages []Package
}

type Package struct {
    Name, Version, Type string        // Type: apk | deb | golang | npm | pypi | maven
    PURL      string
    Source    *SourcePackage          // source package, for indirect matching  (D8)
    Locations []Location              // which file and layer it came from
}

type Advisory struct {                // OSV shape  (D1)
    ID       string                   // CVE-… | GHSA-… | GO-… | ALPINE-… | KVE-…
    Aliases  []string                 // OSV `aliases`  ─┬─ both carry the CVE↔KVE join (D3)
    Upstream []string                 // OSV `upstream` ─┘
    Source   string                   // "osv" | "kisa" — provider provenance
    Kind     Kind                     // vulnerability | malicious  (D15)
    Affected []Affected
    Severity []Severity               // stored as CVSS vectors, banded at query time (D13)
}

type Affected struct {
    Ecosystem string                  // "Go" | "Alpine:v3.19"  (D6)
    Name      string
    Ranges    []Range                 // introduced / fixed events
}

type Finding struct {
    Package  Package
    Advisory Advisory
    Evidence Evidence                 // which range, which comparer, what result  (D10)
}
```

### Storage layout

```
<os.UserCacheDir()>/assay/db/v9/vulnerability.db      override: ASSAY_DB_DIR

buckets:
  advisories   "<ecosystem>\x00<name>"     → []AdvisoryID  primary lookup
  by-source    "<ecosystem>\x00<source>"   → []AdvisoryID  indirect matching (D8)
  by-id        "<advisory-id>"             → Advisory      the record itself, stored once
  enrichment   "<cve-id>"                  → Enrichment    KISA (D3)
  meta         "schema" | "built-at" | "providers"
```

**The lookup buckets hold advisory IDs, not records.** One advisory routinely affects
several packages — measured across the Go dump, 1,452 of 8,510 advisories name more than one
package, up to 22 — so keying records directly by package stores them repeatedly. Measured
blowup is 1.44×, and combined with `by-id` holding its own copy the naive layout turns
21.9 MB of data into 53.6 MB. Resolving an ID through `by-id` costs a second point lookup,
which is microseconds.

| OS | Path |
|---|---|
| Windows | `%LocalAppData%\assay\db\v9\` |
| macOS | `~/Library/Caches/assay/db/v9/` |
| Linux | `~/.cache/assay/db/v9/` (honours `XDG_CACHE_HOME`) |

Values are JSON to start. At a few hundred lookups per scan, bbolt reads are microseconds
and decoding dominates — still tens of milliseconds. Encoding is hidden behind `Store`
and can change without touching callers.

`db update` builds into a temporary file and renames over the live database, so a
concurrent scan never observes a partial write. **Windows rename fails when the target is
open** — see known hazards.

---

## 4. Delivery slices

Cut along working paths rather than architectural layers. A layer on its own cannot run,
and a design that cannot run cannot be validated.

### Slice 1 — Matching core ← first implementation plan

```
CycloneDX SBOM ──▶ Package ──▶ Store(bbolt) ──▶ Matcher ──▶ table
                                   ▲
                           OSV provider (Go / npm / PyPI)
```

**Done when**

- `assay db update` builds a local database from OSV language-ecosystem dumps
- `assay db status` prints each provider's `DataAsOf` and record count
- `assay scan sbom.cdx.json` prints matched CVEs as a table
- A missing database exits 2 with instructions — never an empty clean result
- `Comparer` has table-driven tests covering semver and PEP 440 edge cases
- Differential check against grype on the same SBOM (see §5)

**Fixed here:** all core types, the `Store` / `Comparer` / `Provider` interfaces, exit code
precedence, provenance recording.

### Slice 2 — Containers

`assay scan alpine:3.19`. Registry pull → layer extraction → `/etc/os-release` →
`/lib/apk/db/installed` → `Alpine:vX.Y` lookup.

**Highest design risk.** `Target.Distro`, release-qualified ecosystem keys, and layer
provenance in `Location` all meet reality for the first time here. That is the reason it
comes early rather than late — if the design is wrong, finding out sooner is cheaper.

**Done when** an Alpine image scans end to end, layer digests appear in `Location`, the apk
`Comparer` passes table-driven tests, and the differential check against grype holds.

### Slice 3 — Filesystem and binary targets

`assay scan ./bin/assay` via `debug/buildinfo` (standard library only), and
`assay scan dir:./project` via `go.mod`.

**Insertable anywhere.** It depends on neither slice 2 nor slice 4, costs very little, and
validates the `Source` / `Cataloger` abstraction against a second implementation. If slice 2
stalls, this is the detour.

**Done when** assay scans its own binary.

### Slice 4 — Verdicts and output

`--fail-on`, `--fail-on-unknown`, JSON / SARIF, explain mode. **Exit code 1 first becomes
reachable here.** Severity banding from stored CVSS vectors lands here (D13), which is why
slice 1 stores vectors it does not yet use.

**Done when** output is deterministic and diffable, and explain mode prints a single
finding's `Evidence`.

### Slice 5 — KISA enrichment

KNVD provider → `enrichment` bucket → CVE ID join → Korean descriptions and severity in
reports.

**The prerequisite was investigated on 2026-08-02 and did not resolve.** The blocking
question was whether KNVD offers a machine-readable interface and whether its terms permit
redistribution. Both answers are unfavourable, and a third finding matters more than either:

**Corrected 2026-08-03. The measurement above answered the wrong question.**

It asked whether KNVD could be an independent *matching* source — whether KNVD's own
vulnerability disclosures cover packages assay scans. They do not, and that part stands.

But KNVD has two boards, and the slice looked at the smaller one. `공개된 취약점` is KISA's
own disclosures: 173 records, Korean domestic commercial software. `보안공지` is its security
notices — **2,422 records** — telling Korean organizations to patch CVEs in software they
actually run. Sampled from that board:

```
Apache 제품 보안 업데이트 권고    CVE-2026-23918   Apache HTTP Server 2.4.66 -> 2.4.67
OpenSSL 취약점 보안 업데이트 권고  CVE-2025-11187   OpenSSL 3.4.x/3.5.x/3.6.x
                                CVE-2025-15467   OpenSSL 3.0.x - 3.6.x
```

CVE-keyed, with affected and fixed versions and a Korean title and body. Checked against the
live database, all three are advisories assay already carries, for packages that are in real
containers:

| KISA notice | our record | packages |
|---|---|---|
| CVE-2026-23918 | `ALPINE-CVE-2026-23918` | `apache2`, Alpine v3.20–v3.24 |
| CVE-2025-11187 | `ALPINE-CVE-2025-11187` | `openssl`, Alpine v3.22–v3.24 |
| CVE-2025-15467 | `ALPINE-CVE-2025-15467` | `openssl`, Alpine v3.17–v3.24 |

So a **CVE-keyed enrichment join fires**, which is the shape D27 already builds for NVD:
assay matches through OSV, then attaches what another authority said about the same CVE. What
KISA adds is the Korean title, the Korean description, and the fact that KISA told Korean
organizations to act on it — none of which any other scanner carries.

What has not changed: KNVD as an independent matcher is still not viable, the access story is
still poor (`knvd.krcert.or.kr` deep links 404 for a plain fetch; `boho.or.kr` serves the same
notices and does read), and the licensing question is unresolved — the footer is
all-rights-reserved with no 공공누리 mark, which matters for redistributing a built database
(see *Splitting KISA data into a separate artifact*).

What is not yet measured: how many of the 2,422 notices intersect a typical scan. Three of
three sampled did, but they were the three that surfaced from a search, not a random draw.

**Measured 2026-08-03, against a collected corpus.** ssk had already scraped the 보안공지
board into structured JSON — 2,039 notices, each carrying `cve_id`, `product`,
`problem_version` and `solved_version` already parsed out, plus the Korean title and body.
That answers the access question the first investigation left open, and it supplies the
number that one could not: **17,003 distinct CVE ids**.

Joined against the live database (32,046 advisories):

| | |
|---|---|
| KISA CVEs also carried by assay | **413 (2.4% of KISA)** |
| of those, reachable in `Alpine` | 279 |
| `Go` / `npm` / `PyPI` | 56 / 56 / 37 |
| everything else | 16 |

So the join fires, and it is smaller than the board's size suggests. KISA's corpus is
dominated by desktop and enterprise software — MS 9,968 product entries, Adobe 1,985, Cisco
921 — which assay does not scan. What overlaps is the server-side long tail: OpenSSL, Apache,
Exim, Mozilla.

Against roughly 4,405 Alpine advisories, 279 is about one finding in sixteen carrying a
Korean title and remediation. That is a real feature and a modest one, and it is worth
stating as such rather than as "Korean advisory data" in the abstract.

**The access path is solved, by ssk's own crawler** (`make-kisa-rule/main.py`), which is
where the corpus above came from. KNVD's SPA has an undocumented but working JSON API:

```
POST /api/core/pu/view/count/get        -> total notice count
POST /api/core/pu/view/vuln-notice/get  -> paginated list
     {"collectionType":"VULNOTICE","tabs":"ko","skipCount":N,"limit":50, ...}
```

The list response already carries `content` and `content_html`, so no per-notice detail fetch
is needed — which is why the `detailSecNo.do` deep links returning 404 never mattered. The
publication date is not exposed as a field; the crawler recovers it from the first four bytes
of the Mongo ObjectId, which is the document's creation timestamp.

Two things in that crawler were recorded as not porting to this repo as they stand, and both
were treated as decisions rather than details:

- It disables TLS verification (`verify=False`). A vulnerability scanner turning off
  certificate checking needs a reason stronger than "it worked", so whether the endpoint
  actually requires it has to be established first.
- It parses the affected/fixed version tables out of `content_html` with BeautifulSoup.
  This repo takes no third-party dependencies and Go's standard library has no HTML parser,
  so that looked like the same choice `poetry.lock` forced: a narrow hand-rolled reader over
  the shapes KNVD actually emits, or a dependency decision made deliberately.

**Neither turned out to be real, and the way that was found is worth stating once: calling
the service, not reading about it.** Measured 2026-08-05, against the live endpoint:

- `https://knvd.krcert.or.kr/` verifies strictly — `Verify return code: 0 (ok)`, a
  DigiCert-issued certificate, HTTP 200. The reference crawler's `verify=False` was
  defensive, not required; this repo uses ordinary TLS and never sets
  `InsecureSkipVerify`.
- The list response carries `content_text` alongside `content_html` — already plain text, no
  tags, no parser needed at all. The reference crawler's BeautifulSoup pass over
  `content_html` exists to build the affected/fixed *version tables* into structured rules,
  and D3 already rules that out for enrichment: a title, a summary and a link, never a
  matching source.

Two more things the live service settled, neither anticipated going in and neither found by
reading documentation:

- **KISA's own count endpoint does not work.** `POST /api/core/pu/view/count/get` was probed
  with the list request's own body and three shorter ones; all four answered
  `{"resType":"RES_ERROR","resMsg":"…"}`. There is no total to page against — unlike `nvd`,
  which pages against `totalResults` — so the walk has to detect its own end from the list
  responses alone: it stops on the first empty page after the first, and refuses (rather than
  retrying forever) an empty page at `skipCount` 0, which cannot be the true end of a corpus
  of thousands of notices.
- **KNVD reports its own failures as HTTP 200 with an empty list** — the exact shape the end
  of the corpus takes. Without checking the response's own `resType` field, a service outage
  mid-walk is indistinguishable from having reached the end, and would silently truncate the
  sync rather than fail it loudly.

**KNVD's own vulnerability records number 173, and none of them is in an ecosystem assay
scans.** The `공개된 취약점` corpus is 173 records total, published at roughly one or two a
month since 2024. Every one of the ten most recent describes Korean domestic commercial
software — ipTIME routers, 한컴오피스, 알집, 지니언스 NAC, 나다텔 DVR, 한비로 그룹웨어. Not one
is a Go, npm, PyPI or Alpine package. A CVE-ID join against a container image or a Go module
tree would essentially never fire.

The record *quality* is better than this slice assumed: each carries a CVE ID, a CVSS score
and band, affected and fixed versions, a CWE, and a Korean description. The obstacle is not
the format. It is that the subject matter and assay's targets barely intersect.

**KVE identifiers exist, but nothing on the portal resolves them.** This was checked
specifically, because §1 names KVE as part of why this project exists.

KVE is real: KISA assigns the numbers, and third parties cite concrete ones — a networking
vendor's own patch notice references `KVE-2023-6187`, and bug-bounty trackers list
`KVE-2024-0770` and `KVE-2024-0771`. What could not be found is any public KNVD record under
one. Measured through the portal's own integrated search:

| query | 공지사항 | 보안공지 | 공개된 취약점 |
|---|---|---|---|
| `KVE-2024-0771` | 0 | 0 | 0 |
| `KVE` (bare string) | 0 | 0 | 0 |
| `CVE-2026-24498` *(control)* | 0 | 0 | **1** |

The control matters: without it, zero results would be indistinguishable from a broken
search. The search works; the string `KVE` simply does not occur anywhere in the portal's
published content, and every published record is titled and keyed on its CVE
(`CVE-2026-24498 | EFM-Networks ipTIME …`).

The reading that fits: a KVE number is assigned during the report-handling workflow
(신고 → 분석·검증 → 개발사 전달) and travels in correspondence and vendor patch notices, while
the portal publishes under CVE. Secondary sources still describe KVE as "checkable on KNVD",
but the portal was rebuilt — `resultList.do`, `detailSecNo.do` and `rewardExplain.do` all
return errors now — so those descriptions may predate the rebuild.

**Not established:** whether the previous portal published KVE records, whether a logged-in
account sees them, and whether a KVE→CVE mapping exists anywhere retrievable. Each would need
asking KISA directly.

**What this means for the design.** §1's premise stands as written — KISA does publish KVE
identifiers — but D3's `Aliases`/`Upstream` "CVE↔KVE join" has no public KVE side to join
against today. That join is not load-bearing: reading both fields was independently confirmed
necessary *within OSV* (Go records carry the CVE in `aliases`, Alpine records in `upstream`),
so D3 survives on its own evidence regardless of KVE.

**Access.** Two documented RSS feeds exist — `/rss/security/notice` and
`/rss/security/info` — and each returns only the latest **10** items, with no bulk export,
no date range, and no pagination. The site is a Vue SPA served by an undocumented POST API
(`/api/core/pu/view/…`) which does paginate, but it is not a *published* interface: the
portal was rebuilt recently and its previous deep links (`detailSecNo.do?IDX=…`) now return
a server error, so nothing about it was ever a stable contract. No corresponding dataset was
found on 공공데이터포털. `internal/provider/knvd` is built to survive exactly that
instability rather than assume it away — a `resType` check on every page (the count-endpoint
and empty-list findings above), a repeated-first-ID guard against a service that stops
honouring `skipCount`, and a retry policy that treats anything not definitely permanent as
transient.

**Terms.** The site footer reads `Copyright(C) 2026 KISA. All rights reserved.` with no
공공누리 (KOGL) mark. Korean public bodies that permit reuse label content with a KOGL type;
its absence alongside an all-rights-reserved notice is not permission. This is what D29
resolves: built locally, stripped before publishing, until that changes.

**Shipped 2026-08-05.** `internal/provider/knvd` fetches the notices, `internal/advisory`
and the `enrichment` bucket (schema 7) hold one record per CVE a notice names,
`Matcher.annotate` attaches them to a finding by CVE exactly as NVD's ratings are, and the
table, `--explain` and JSON all render them. `KISA_ENABLE` gates the fetch in `db build`, the
same shape `NVD_ENABLE` already has. What D3 said from the start held all the way through:
enrichment changes no verdict, no severity and no exit code — it is prose for a reader.

**Revisit whether KNVD could become an independent matching source when** assay's targets
include hosts or workstations rather than container images and source trees, which is when
한컴오피스 and ipTIME firmware become things a scan could encounter — the same trigger
`docs/deferred-decisions.md` already records for that question. That question is separate
from enrichment and remains open; enrichment itself does not wait on it and already has a
user.

### The first full-corpus build, 2026-08-05

Slices ⑦, ⑧ and ⑤ were merged and then run together for the first time, on a build server
rather than in CI, with every window unbounded: **6h31m**, 32,272 advisories, NVD's whole
feed at **354,067** rated CVEs, KISA at **18,523** enrichment records drawn from 2,971
notices, 256 MB on disk. Published as `ghcr.io/kun9497/assay-db:v7`.

Three things it measured that no test could:

- **The timeout fix is load-bearing.** The run before it died at 3h50m and 262,000 records
  on a client timeout classified as permanent — `net/http`'s `timeoutError.Is` answers true
  for `context.DeadlineExceeded`, so the deny-list let it through as fatal. The v7 run hit
  the same family once, an HTTP/2 `stream error`, and recovered in **5 seconds**. The
  identical failure cost 116 minutes before the fix and 5 seconds after it.
- **D29 holds on the real artifact, not only in the test.** The published layer was pulled
  back into a clean directory and read as bytes: the local build carries **1,719,126**
  Hangul sequences and 18,524 `knvd.krcert.or.kr` occurrences, the published artifact
  **zero** of each. That is the check route 6 above defeated, run against the file users
  actually download.
- **A scan against the pulled artifact behaves identically** apart from the absent Korean —
  same findings, same bands, same exit codes across `--fail-on critical|high|medium|low`.
  D3's "enrichment changes no verdict" is now checked end to end rather than only in a unit
  test.

### Slice 9 — Versions the comparers cannot read ← next

A package whose version will not parse is reported as **skipped** and never folded into a
clean verdict (D20, D21), so this is loud rather than silent. It is still a vulnerability
that went un-assessed, which is what D9 says directly: *treating an unparseable version as
"not vulnerable" is a miss.*

Measured 2026-08-06 against the v7 database — every range bound of every advisory, fed to
the comparer that owns its ecosystem:

| comparer | bounds it cannot parse | bounds | packages |
|---|---:|---:|---:|
| semver (Go, npm) | 96 | 29,840 | 42 |
| pep440 (PyPI) | 45 | 31,147 | 14 |
| apk (Alpine) | 61 | 53,819 | 30 |

0.18% overall, and the cause is not exotic. The dominant shape is a version with **fewer
components than the grammar demands**: `github.com/canonical/lxd` at `4.0`, `6.0` and `6.5`,
`next` at `13.0`, `github.com/cosmos/cosmos-sdk` at `0.46`. Semver requires three
components; upstream advisory text routinely writes two. The rest are genuine oddities —
`libdwarf` at `1999-12-14` (a date), `buildbot` at `0.7.11p3`, `neutron` at `7.2.0-12.1`.

Two were met in live scans the same day. `alpine:3.14` skipped `libretls 3.3.3p1-r3`, and
with it CVE-2022-0778; a scan of assay's own binary skipped `github.com/docker/cli` because
a GHSA range bound reads `19.03.0`, whose `03` is the leading-zero numeric identifier semver
forbids.

**The open question is per-ecosystem leniency, and D9 forbids answering it once for all
three.** Whether `4.0` may be read as `4.0.0` in a semver ecosystem, whether apk should
accept a letter followed by digits (`3.3.3p1`) as Alpine's own package versions imply
apk-tools does, and whether pep440 should accept a `p3` patch suffix are three questions with
three different upstream authorities. Each needs its own decision, its own table-driven
cases, and its own check against that ecosystem's published vectors — the apk comparer
already stands against apk-tools' 738 comparisons, and that is the bar. One shared "be
lenient" rule is precisely the collapse D9 exists to prevent.

Nothing here may make a version compare **lower** than it does today. The failure being
fixed is a miss, and a lenient parse that reorders versions already handled correctly would
trade a loud miss for a silent one.

### Slice 10 — Which KISA notice wins

Found on first real use, 2026-08-06, and measured against the v7 database. Two defects, one
cause.

**The store resolves a tie by arrival order, which D25 forbids.** The enrichment bucket is
keyed `(CVE, Source)` and every KISA record carries the same source, so a CVE named by two
notices keeps whichever arrived last. The build's own log holds the number: `convert` emitted
**20,314** records and the store kept **18,523**, so **1,791** were overwritten by page
order. D25 settled this for ratings — *never resolve a tie by arrival order; that was the
defect, not a harmless coin flip* — and the enrichment bucket repeated it.

**Most notices are monthly roundups, and they win those ties by volume.** Of 1,935 distinct
notices, 804 name exactly one CVE, while 38 name more than a hundred and `MS 7월 보안 위협에
따른 정기 보안 업데이트 권고` alone names **1,046**. **12,997 of 18,523 stored records (70%)**
come from a notice claiming more than 20 CVEs. Every enriched finding met in live scanning —
`openssl` CVE-2024-5535 on `node:14-alpine`, `curl` CVE-2024-6197 on `nginx:1.25.3-alpine` —
attached a Microsoft monthly patch bulletin to a non-Microsoft vulnerability. The specific
notices that make the feature worth having do exist (`OpenSSH 제품 보안 업데이트 권고` for
regreSSHion, `XZ-Utils 보안 주의 권고` for CVE-2024-3094, `BIND DNS 취약점 보안 업데이트 권고`)
and lose to a roundup whenever both name the same CVE.

The likely rule is **the narrowest notice wins** — fewest CVEs claimed, ties broken on the
notice ID so two runs agree — which removes the arrival-order dependence and the roundup
dilution together. A third defect rides along: 2,202 records (12%) carry a summary that
begins from the `제목없음` fallback because the `□ 개요` heading was not found.

Enrichment changes no verdict (D3), so none of this can produce a wrong answer. That is why
it is queued behind slice 9 rather than ahead of it.

---

## 5. Verification

**Differential testing against grype is the primary correctness check**, repeated every
slice. The same SBOM or image goes through both tools and the results are compared.

Exact agreement is not expected — the data sources differ. The signal is magnitude: a large
divergence means our matcher is wrong. This is the cheapest strong oracle available, and it
costs nothing to run.

### Measured: `registry.access.redhat.com/ubi9/ubi`, 2026-08-07

Run against grype 0.104 (database built 2026-08-02) and assay's own database built from the
2026-08-05 CSAF VEX archive. Both tools read the same image digest, `sha256:73f6c558`.

| | |
|---|---|
| grype findings | 418 |
| assay findings | 415 |
| in both | **415** |
| assay-only | **0** |
| grype-only | 3 |
| fix-state disagreements on shared findings | **0** |

**assay was a strict subset of grype here, and the difference was entirely data recency.** All
three grype-only findings came from two CVEs whose VEX documents were created on 2026-08-06,
the day AFTER the archive assay read: `changes.csv` timestamps them
`2026-08-06T03:46:10` and `2026-08-06T12:51:52`, and neither document is present in
`csaf_vex_2026-08-05.tar.zst`.

**Re-run the same day with the archive delta (D49): 418 grype, 418 assay, 418 in both, zero on
either side.** Exact agreement, which the section above says is not expected — and it is worth
being precise about why it happened rather than treating it as a target. The two tools read the
same image and, once the recency gap closed, the same statements from the same vendor. It will
stop being exact the moment either side's data moves.

Both tools also agree on the substance: assay evaluated all 186 packages with none skipped,
found 415 findings and rated **all 415 unfixable**; grype's fix state for those same 415 is
404 `not-fixed` plus 11 `wont-fix` — no fix available, unanimously. A ubi9 image is fully
patched against everything Red Hat has actually fixed, which is what makes it a good test of
D48 specifically: without the VEX provider every one of those 415 would have been reported
clean.

**The run earned its keep.** It found a false positive nothing else had: assay reported
CVE-2022-2309 against `python3`, where Red Hat's document names
`python3-lxml::inkscape:flatpak`. The `::` module context was being read as an epoch
separator, truncating package names across 828 CVEs. See D47's `splitContext`.

### Measured: `registry.access.redhat.com/ubi8/ubi`, 2026-08-07

The same comparison against RHEL 8, once the BerkeleyDB backend landed (D44). Before it, this
image produced **0 findings against grype's 504** — the format refusal came before any matching.

| | |
|---|---|
| grype findings | 504 |
| assay findings | 517 |
| in both | 496 |
| assay-only | 21 |
| grype-only | 8 |
| fix-state disagreements on shared findings | **0** |

**Every divergence has an answer, and neither side is wrong.**

The 8 grype-only findings were recency again: CVE-2026-8458 and CVE-2026-18839 written
2026-08-06 and CVE-2026-12143 on **2026-08-07**, all after the 2026-08-05 archive. **With the
delta they are gone: 504 grype, 526 assay, all 504 in both, zero grype-only.**

The 21 assay-only findings are **D8 doing its job on data grype's source does not carry**. Red
Hat's `known_affected` lists name SOURCE packages — `python-chardet.src`, `python-idna.src`,
`python-urllib3.src` — at mainline RHEL 8 with no fix, and assay reaches them through the
installed binary's `SOURCERPM`. Eighteen of the twenty-one are that; `--explain` says so on
every one:

```
package:  python3-chardet 3.0.4-7.el8 [Red Hat:8]
matched:  python-chardet (source package, D8 — installed package is python3-chardet)
result:   3.0.4-7.el8 is at or above any earlier version, with no fixed version recorded
```

The other three are `subscription-manager-rhsm-certificates`, named by Red Hat under its own
name for three bundled JavaScript dependencies. Each of the twenty-one was checked against the
VEX document it came from: all named, all mainline RHEL 8, all `known_affected` with no fix.

**This is the first divergence where assay reports MORE than grype and is right to.** It is
not a claim to be better — it is the source-package indirection D8 exists for, reaching a
statement Red Hat publishes and grype's upstream does not expose.

Beyond that:

- `Store` is an interface, so `Matcher` is tested against an in-memory fake — no database
  needed to test matching logic.
- **`Comparer` carries the highest test density.** Table-driven, per ecosystem: deb epochs,
  apk `-rN` suffixes, semver pre-release precedence, PEP 440 `.post` / `.dev`. This is where
  false negatives originate.
- The bbolt implementation is tested separately against a small fixture database.

---

## 6. Benchmarking notes

Design elements taken from existing tools, and what was left behind.

**From trivy**

- Database as an OCI artifact (`ghcr.io`) — registry distribution gets mirroring, auth, and
  air-gapped operation for free. *Deferred; see deferred-decisions.*
- bbolt for the local store — same access pattern, same conclusion. *Adopted (D4).*
- Splitting optional data into its own artifact (`trivy-java-db`) — maps onto KISA data.
  *Deferred.*
- Committing collected upstream data to git (`vuln-list`) for an audit trail. *Deferred.*
- **Not taken:** breadth into config, secret, IaC, and Kubernetes scanning.

**From grype**

- Indirect matching through source packages. *Adopted (D8) — this one prevents false
  negatives, so it is in from the start.*
- Schema version as a directory, rebuild instead of migrate. *Adopted (D5).*
- A clean "SBOM in, findings out" internal boundary, even though assay also builds the
  inventory. *Adopted — it is the shape of §3.*
- **Not taken:** depending on a database schema we do not own, which would foreclose KISA.

---

## 7. Related documents

- [`README.md`](../../../README.md) — user-facing description
- [`CLAUDE.md`](../../../CLAUDE.md) — working constraints for Claude Code sessions
- [`docs/deferred-decisions.md`](../../deferred-decisions.md) — postponed work, known
  hazards, unverified assumptions
