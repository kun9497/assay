# Compatibility

What a consumer of `assay`'s output can rely on across releases, and what a version bump
means. `assay` is pre-1.0: a breaking change can still happen, but never silently. It comes
with a version bump, a **Breaking** entry in the [changelog](../CHANGELOG.md), and a
"Compatibility" section in the release notes.

## Versioned contracts

| Contract | What it is | Version field | Current |
|---|---|---|---|
| `report` | `assay scan --output json` | `schemaVersion` | 20 |
| `provenance sidecar` | the file `--provenance <path>` writes (D120) | `schemaVersion` | 1 |
| `status.json` | the published database's status, on the `status` branch (D138) | `schemaVersion` | 1 |
| `db status` | `assay db status --output json` (D147) | `schemaVersion` | 1 |
| `truthset labels` | `testdata/groundtruth/labels.json`, the ground-truth labels `cmd/truthset` reads (D161) | `schemaVersion` | 1 |
| `truthset report` | the file `truthset -out <path>` writes (D161) | `schemaVersion` | 2 |
| `database` | the local store and the OCI tag `ghcr.io/kun9497/assay-db:vN` | tag `vN`, `db status` `schema:` | 9 |

Tests hold this table to the constants in the code, so it cannot fall behind a bump.

## The JSON report

**Every change to the document bumps `schemaVersion`.** That includes a new optional field.
A consumer can tell "the format I know" from "something I have not seen" by the number alone.

A bump is one of two kinds, and the changelog says which:

- **Additive**: fields are added, and every existing field keeps its name, type and meaning.
  Every bump so far has been of this kind, with the exceptions noted below (schemas 12 and 18).
- **Breaking**: a field is removed or renamed, changes type, or changes meaning. None has
  removed or renamed a field to date.

To read it safely:

- Ignore fields you do not know. New ones arrive in minor releases.
- Check that `schemaVersion` is at least the version that introduced the fields you read,
  rather than equal to one number. A consumer pinned to `== 12` broke on 13 for no reason.

**Where the history fell short of this.** Recorded so a long-running consumer can check what
it relied on:

- Schema 12 (v0.6.0; 11 was never released) changed what `summary.targetIncomplete` counts:
  since D109 it includes manifests that could not be read. The release notes warned that
  `--fail-on-incomplete=target` could now exit 2 where it had passed, but also said no field
  changed meaning, which was wrong for this one.
- v0.10.0 started filling `purl` on an image's OS packages (D121), where it had been empty.
  The bump to 14 that release was made for `provenance`.
- Three additions reached a release without a bump, so two releases with the same
  `schemaVersion` differ: `crossMappedFrom` (D108, v0.5.0, schema 10), and
  `locations[].install` and `provenance.database.artifact.signedBy` / `unverified` (D137,
  v0.11.0, schema 14). Each is optional. The rule above, a bump for every change, applies
  from schema 15 on.
- Schema 15 (additive) added `ratings[].cvssV2`, true when a rating's band came from NVD's
  CVSS v2 fallback (D156). A rating whose only scorable entry is a CVSS v2 base vector,
  rated `unknown` before, now carries a band, so `--fail-on` can trip where it did not.
- Schema 16 (additive, no new field): `unread[]` may name a path inside an image that the
  layer walk could not resolve (a symbolic link chain past Linux's limit of 40, or a cycle),
  not only a manifest or directory, and `summary.unreadManifests` counts it. Its `reason`
  says which. The table's count reads "path(s) not read", and SARIF `assay/not-read`
  describes a path rather than a manifest.
- Schema 17 (additive, no new field): `coverage[].dataAsOf` is when the provider's data for
  THAT KEY was current — the key's own archive date where the provider recorded one
  (`Provenance.KeyAsOf`, D113 revised 2026-11-09), the provider's `DataAsOf` otherwise, and
  on a whole-key frozen key its freeze date. Before, it was the provider's `DataAsOf` for every
  key, so it always equalled `db status` `providers[].dataAsOf`; now it can be later than that
  (Amazon Linux 2023 beside Amazon Linux 2, Debian 12 beside the stalest OSV archive). A
  database built before the field records no per-key date and the value reads as before.
- Schema 18 (**breaking** for a consumer switching on `inventoryScope.applicationPackages`;
  additive otherwise): that field gains a fourth value, `partial` — an image scan now reads
  npm packages under the global `node_modules` roots and Go binaries in the standard bin
  directories (D160) and still reads no Python, Java or other application packages — and
  `inventoryScope.applicationScope[]` (new, image targets only) says per ecosystem whether it
  was `read`, `none` (probed, nothing there) or `not-read`, with the `roots` a probe reads.
  Every image scan's `applicationPackages` is `partial` from this schema on; `not-read` no
  longer occurs for it.
- Schema 19 (additive): `findings[].package.locations[].ownedBy` — `{name, version}` of the
  OS package whose file list names the location's path (D162), present on an image's probed
  application packages (D160) when the distro's own package installed the file: rpm's
  BASENAMES/DIRNAMES, apk's `F:`/`R:` lines, dpkg's `info/*.list`, pacman's `files`.
  Exact-file ownership, and only when the file's layer is not later than the record's (a file
  the image author replaced over the package's is unowned); absent when no OS package lists
  the file or outside an image.
- Schema 20 (additive): `findings[].advisory.related` — the record's own `related` identifiers.
  For Amazon ALAS, Fedora Bodhi and Oracle OVAL records it is where the CVE a finding fixes is
  named (none of them has an `aliases` or `upstream` field); the table and `--explain` always
  read it, the JSON did not, so before schema 20 such a finding reached its CVE only through
  `ratings[].advisoryId`.

## The provenance sidecar, status.json and `db status`

All three follow the report's rules with their own `schemaVersion`. Two notes:

- The sidecar embeds the report's `provenance` object. That object changes under the
  report's `schemaVersion`, not the sidecar's, so read both numbers.
- `status.json`'s `published.schemaVersion` is the database schema of the artifact on the
  tag, not the version of `status.json` itself.

## The database

The schema is part of the tag: `assay db update` pulls `assay-db:v<N>` for the schema the
binary reads, and `assay db ref` prints that tag. A binary reads exactly its own schema. It
never migrates one in place: a scan or `db status` that meets another schema exits 2 and
says to run `assay db update`, and `db update` refuses an artifact of another schema before
downloading it. Upgrading `assay` across a schema bump therefore means one `db update`.
A CI cache must be keyed on `assay db ref` (see [The database](DESIGN.md#the-database)).

The schema has been 9 since v0.1.0.

## SARIF

The output is SARIF 2.1.0. It carries no version of its own, so the stable parts are named
here:

- Finding rule ids are `<advisory id>-<package name>`.
- The rules `assay/not-evaluated`, `assay/not-read`, `assay/frozen-data` and
  `assay/inventory-scope` keep their ids and meanings.
- The `partialFingerprints` key `assay/pkg-advisory/v1` names the fingerprint scheme. A
  change to how fingerprints are computed ships as a new key, so existing code-scanning
  alerts are not silently re-identified.

## What does not change without a major version

- **Exit codes** (D11): `0` no `--fail-on*` gate tripped (not "no findings": without a gate,
  with every finding waived, or with an empty document the exit is 0 too — read `summary`), `1`
  findings at or above a `--fail-on*` gate, `2` could not run or the result cannot be trusted,
  with `2` outranking `1`.
- **Stream discipline**: results on stdout, diagnostics on stderr.
- **Flag names.** A flag's meaning can be narrowed or extended with a release note; a flag
  is not renamed or removed.
- **Table output is for people.** Its layout can change in any release; parse JSON or SARIF
  instead.
