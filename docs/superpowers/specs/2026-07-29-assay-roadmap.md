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

Two things distinguish it from existing scanners:

- **Korean advisory data.** KISA/KNVD publishes advisories and KVE identifiers covering
  software that NVD and OSV pick up late or not at all.
- **Explainable matches.** Every finding carries the evidence that produced it — which
  range, which comparer, which comparison result.

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

`<cache>/assay/db/v1/vulnerability.db`. A schema change means rebuilding into a new
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

### D14 — The scan path never touches the network

`assay db update` is the only command that needs network access. A missing or
schema-mismatched database produces exit code 2 with instructions — never an automatic
download, and never a silently empty result.

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
| `--fail-on-unknown` | No grype equivalent. Exists because unknown is not in assay's severity ordering (D17). |

Add a row here whenever a shared name gains different semantics. A silently divergent flag
is worse than a differently named one.

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
<os.UserCacheDir()>/assay/db/v1/vulnerability.db      override: ASSAY_DB_DIR

buckets:
  advisories   "<ecosystem>\x00<name>"     → []Advisory    primary lookup
  by-source    "<ecosystem>\x00<source>"   → []Advisory    indirect matching (D8)
  by-id        "<advisory-id>"             → Advisory      explain, alias resolution
  enrichment   "<cve-id>"                  → Enrichment    KISA (D3)
  meta         "schema" | "built-at" | "providers"
```

| OS | Path |
|---|---|
| Windows | `%LocalAppData%\assay\db\v1\` |
| macOS | `~/Library/Caches/assay/db/v1/` |
| Linux | `~/.cache/assay/db/v1/` (honours `XDG_CACHE_HOME`) |

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

**Blocked on a prerequisite:** confirming that KNVD offers a machine-readable interface and
that its terms permit redistribution. That unknown is why this is last — if it does not
resolve, the preceding four slices still stand on their own.

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
