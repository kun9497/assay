# Compatibility

What a consumer of `assay`'s output can rely on across releases, and what a version bump
means. `assay` is pre-1.0: a breaking change can still happen, but never silently. It comes
with a version bump, a **Breaking** entry in the [changelog](../CHANGELOG.md), and a
"Compatibility" section in the release notes.

## Versioned contracts

| Contract | What it is | Version field | Current |
|---|---|---|---|
| `report` | `assay scan --output json` | `schemaVersion` | 15 |
| `provenance sidecar` | the file `--provenance <path>` writes (D120) | `schemaVersion` | 1 |
| `status.json` | the published database's status, on the `status` branch (D138) | `schemaVersion` | 1 |
| `db status` | `assay db status --output json` (D147) | `schemaVersion` | 1 |
| `database` | the local store and the OCI tag `ghcr.io/kun9497/assay-db:vN` | tag `vN`, `db status` `schema:` | 9 |

Tests hold this table to the constants in the code, so it cannot fall behind a bump.

## The JSON report

**Every change to the document bumps `schemaVersion`.** That includes a new optional field.
A consumer can tell "the format I know" from "something I have not seen" by the number alone.

A bump is one of two kinds, and the changelog says which:

- **Additive**: fields are added, and every existing field keeps its name, type and meaning.
  Every bump so far has been of this kind, with the exception noted below.
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
  CVSS v2 fallback (D156). Ratings that carry no v3 or v4 vector, rated `unknown` before,
  now carry a band, so `--fail-on` can trip where it did not.

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

- **Exit codes** (D11): `0` clean, `1` findings at or above a `--fail-on*` gate, `2` could
  not run or the result cannot be trusted, with `2` outranking `1`.
- **Stream discipline**: results on stdout, diagnostics on stderr.
- **Flag names.** A flag's meaning can be narrowed or extended with a release note; a flag
  is not renamed or removed.
- **Table output is for people.** Its layout can change in any release; parse JSON or SARIF
  instead.
