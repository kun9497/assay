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

`<cache>/assay/db/v7/vulnerability.db`. A schema change means rebuilding into a new
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
end-user path. The artifact's tag is the schema version (`Ref` renders it as `:v7`), so a
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
<os.UserCacheDir()>/assay/db/v7/vulnerability.db      override: ASSAY_DB_DIR

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
| Windows | `%LocalAppData%\assay\db\v7\` |
| macOS | `~/Library/Caches/assay/db/v7/` |
| Linux | `~/.cache/assay/db/v7/` (honours `XDG_CACHE_HOME`) |

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
