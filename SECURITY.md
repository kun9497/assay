# Security policy

## Reporting a vulnerability

Report it privately through GitHub:
**[Security → Report a vulnerability](https://github.com/kun9497/assay/security/advisories/new)**.
Please do not open a public issue for it.

Include what you ran (the `assay version` line, the command, the target or a minimal
reproduction) and what you observed. If the report is about the published database,
include the `pulled:` and `signed:` lines from `assay db status`.

`assay` has one maintainer. A report is acknowledged within seven days, and you will
hear what is being done about it and when a fix is expected. A fix ships as a new release
and a GitHub security advisory crediting you, unless you ask not to be named.

## What to report privately

Anything that lets someone make `assay` give a wrong answer on purpose, or reach the people
who run it:

- **A way to hide a vulnerability from a scan**: a crafted image, SBOM, lockfile or
  binary that makes a package go unread, or read under the wrong identity, *without* the
  scan saying so (an exit 0 where the result should have been incomplete).
- **The supply chain**: getting `assay db update` or `db build --seed` to install a
  database the project's keys did not sign (D137), getting `install.sh` to install a binary
  its checksums signature does not cover, or anything in the release and publish
  workflows that would let an outsider change what is published.
- **The scanning host**: path traversal or symlink escape out of an image layer, a tar or
  zip member, or a scanned directory; unbounded memory or disk from a crafted input (D112
  sets the bounds); registry credentials printed or sent where they should not go (D118).

## What to report as a normal issue

A **missed or extra finding on real data** (a false negative or a false positive) is a
correctness bug, and the most useful report this project gets. Open a
[public issue](https://github.com/kun9497/assay/issues) with the target and the advisory
ID, so the fix and the reasoning are visible to everyone who relies on the same result.
If the miss affects many users and you would rather it not be public before a fix, use the
private route above. Either is fine.

Known limits are not vulnerabilities: what a scan does not cover is listed in
[docs/DESIGN.md](docs/DESIGN.md#scope) and [docs/deferred-decisions.md](docs/deferred-decisions.md),
and each scan says on stderr what it did not read.

## Supported versions

Fixes go into the next release; there are no backport branches. Use the
[latest release](https://github.com/kun9497/assay/releases/latest). The published database
is rebuilt nightly for the schema the latest release reads.

## Verifying what you download

- **Release binaries**: each release's `assay_<version>_checksums.txt` is signed (the
  `.sig` beside it), and `install.sh` (and `install.ps1` on Windows) verifies the signature
  against the keys it embeds before it checks a checksum. v0.10.0 is the first signed
  release.
- **The database**: `assay db update` verifies the artifact's cosign signature against keys
  built into the binary before writing anything, and refuses an unsigned artifact unless
  `--allow-unsigned` is passed (which `db status` then records). The public keys are in
  [`internal/dbcmd/trust/keys/`](internal/dbcmd/trust/keys/).
- **Freshness**: [`status.json`](https://raw.githubusercontent.com/kun9497/assay/status/status.json)
  records the last nightly publish and what the tag serves now (D138).
