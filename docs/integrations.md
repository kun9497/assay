# CI integration

*English · [한국어](integrations.ko.md)*

`assay scan` is built to be gated on: results go to stdout, diagnostics to stderr, and the
exit code is a contract — `0` no gate tripped, `1` a finding at or above your threshold, `2` the
scan could not run or its result cannot be trusted, with `2` outranking `1` outranking `0`. That
is all a pipeline needs for the verdict. `0` is not "no vulnerabilities", though: a scan with no
`--fail-on*` flag lists its findings and exits 0, and so does one whose findings were all waived
(`summary.suppressed`) or an SBOM with no components (`summary.components: 0`). A pipeline that
also needs to see what was found, or to refuse an empty inventory, reads the JSON `summary`.

Two complete, copy-pasteable examples:

- **[GitHub Actions](ci/github-actions.yml)** — scan on push, record findings in the
  Security tab (SARIF), fail the build on a high-or-worse finding.
- **[GitLab CI](ci/gitlab-ci.yml)** — scan in a job, keep the report as an artifact, fail
  the pipeline on the exit code.

Both install `assay` from the commit the latest release was built from, as the README's
one-liner does (the release job keeps all three current); a branch name there would move under
you. The GitLab job also installs `openssl`, because `install.sh` verifies the release's
checksums signature with it (D137) and the `alpine` image does not ship the binary — without
it the installer refuses to install rather than skip the check.

## The pattern, in one line

```bash
assay scan <target> --fail-on high        # exit 1 at or above high; exit 2 if untrustworthy
```

`<target>` is a registry image, a `docker-archive:`/`oci-dir:` path, an SBOM, a binary, or
a directory. Add `--output sarif` (or `json`) to write a machine-readable report to stdout
— redirect it to a file. `--fail-on` also takes `--fail-on-kev`, `--fail-on-epss <n>`,
`--fail-on-eol`, and `--fail-on-unfixable[=wont-fix]`; combine as many as you gate on.

## Record findings, then gate — in that order

The GitHub example runs the scan once, writing SARIF to a file, then uploads that file with
`if: always()` **before** letting the exit code fail the build. This is deliberate: a build
that fails its gate should still leave the findings recorded, not throw them away. Uploading
after a failed step, or letting `--fail-on` abort before the upload, loses the record the
Security tab exists to keep.

```yaml
- name: Scan
  id: scan
  run: |
    set +e
    assay scan "$IMAGE" --output sarif --fail-on high > assay.sarif
    echo "exit_code=$?" >> "$GITHUB_OUTPUT"
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: assay.sarif, category: assay }
- name: Fail on findings
  run: exit ${{ steps.scan.outputs.exit_code }}
```

If `$IMAGE` can name a target this pipeline does not fully trust — a tag a PR supplies, a
registry outside the org — add `--timeout <duration>` (D112): reads are already size-bounded,
but `--timeout` is what turns a pull or layer walk that simply will not finish into exit 2
instead of a hung job.

Add `--db-max-age <duration>` and `--db-max-rating-age <duration>` (D113) if the pipeline
wants a freshness guarantee: neither flag defaults to anything, so a service or CI gate that
cares has to name the age it accepts. `--db-max-age` judges only the ecosystem keys the
scan's inventory actually uses and stays blind to ratings on purpose (D59); pass
`--db-max-rating-age` separately to cover NVD/EPSS/KEV, since ratings are additive and get
their own gate rather than widening the first one.

This gate covers the image's operating-system packages. npm, Python, Java and Go
dependencies installed inside the image are not inventoried by an image scan (D70,
[deferred](deferred-decisions.md)), so a pass here says nothing about them — for those, gate
the application's own lockfile or source directory (`assay scan dir:.`), its built binary or
jar, or an SBOM of the image. Every image scan says this itself (D141): a `note:` line on
stderr, and an `assay/inventory-scope` note in SARIF, so the code-scanning tab never shows an
empty image scan without it.

The `security-events: write` permission is what lets the workflow upload to code scanning.

## The database

`assay db update` pulls the published database from `ghcr.io/kun9497/assay-db` — an OCI
artifact, seconds not hours, **public** since 2026-08-28, so the pull needs no login and no
packages permission. If your pipeline cannot reach ghcr.io at all, run `assay db build`
instead — it builds the database from upstream sources with no external artifact, at the
cost of time.

The published artifact is signed (D137), and `db update` verifies the signature against the
keys built into the binary before it installs anything — so a database that reaches your
pipeline through a mirror is only installed if the mirror copied the signature too. The
signature is a second tag beside the artifact, `sha256-<digest>.sig`. A pull-through cache
serves it on demand, because assay asks for that tag by name. A mirror filled by copying one
tag (`crane copy …:v9 <mirror>:v9`, `oras cp`) does not have it: copy the signature tag too
(`crane copy ghcr.io/kun9497/assay-db:sha256-<digest>.sig <mirror>/assay-db:sha256-<digest>.sig`,
or `crane copy --all-tags` on the repository). Without it `db update --from <mirror>` stops with
`is not signed` and the tag name to copy. `--allow-unsigned` installs anyway, with a
`WARNING` on stderr and `signed: NO (--allow-unsigned)` in `db status` and in every report's
provenance; a signature that is present and does not verify is refused regardless, because
that is the case the signature exists for. `db build --seed` applies the same check with no
opt-out.

**Is the published database current?** The publish job writes [`status.json`](https://raw.githubusercontent.com/kun9497/assay/status/status.json)
after every nightly run, from the live tag rather than from the run's own log:

- `lastSuccess.finishedAt`: the last nightly that published. The nightly runs every 24 hours,
  so alert when this is older than about 36 hours.
- `lastRun`: the most recent nightly, whatever its result.
- `published`: what `db update` fetches right now: `digest`, `builtAt`, `dataAsOf` (with
  `dataAsOfSource`) and `signed`/`signedBy`. `signed: false` means every `db update` is being
  refused until the publisher signs the digest.

A failing ops workflow also keeps one pinned issue open in this repository until it recovers.

`db update` retries a layer download that is cut mid-stream, three attempts in all (D140).
Request-level failures (a 5xx, a 429, a connection dropped before the response) were already retried. Every scan prints
a warning on stderr when its database was built more than seven days ago (D139). It is a nudge,
not a gate, and leaves the exit code and stdout alone; `--db-max-age` remains the way to fail
a scan on stale data.

The database is orthogonal to the scan: update it once per job (or cache it), and every
`assay scan` after that only reads it. A scan of an SBOM or a local tarball makes no network
call at all.

## Operating assay on targets you did not author

Written for a service or shared runner that scans images or SBOMs its operator did not
produce — the boundary the 2026-11-04 QA named. Everything below is readable from the JSON
report or from `assay db status --output json`; nothing needs stderr.

- **Choose the ignore file; never discover it.** Run every scan with `--config none`, or with
  `--config <path>` naming a file the operator owns. Without `--config` a scan applies
  `.assay.yaml` from its working directory (that directory only, not its parents), so a checkout
  can waive its own findings. The provenance records which: `provenance.waivers.ignoreFile.path`
  is `"none"`, or the path with `discovered: false`.
- **Refuse or label an empty inventory yourself.** `summary.components == 0` exits 0 by design,
  as a scan with no `--fail-on*` gate does. A pipeline that must not read "nothing read" as
  "nothing found" reads `summary.components` and decides; assay does not decide for it.
- **Show "EOL unknown" when `eol` is absent.** The key is omitted when no release could be
  matched — no distro identity, an unrecognised release, no end-of-life row — or when the
  database carries no end-of-life data at all (`assay db status --output json` shows
  `eol.releases: 0`; `db update` fixes that one, unlike the other three). The reason reaches
  stderr only, and only under `--fail-on-eol`; `distro.recognized` says whether the release was
  understood at all. When `eol` is present, show `eolFrom`, `eolLabel`, `eoesFrom` and
  `eoesLabel` as they are.
- **Show frozen keys as frozen.** `coverage[]` has one record per ecosystem key the inventory
  holds, with `state`, `provider`, `dataAsOf` (when that provider's data for that key was
  current; on a whole-key frozen key, its freeze date) and, on a frozen key, `frozenSince`;
  `summary.frozenKeys` counts them and every finding on such a key carries `frozenSince`. A
  frozen key's data stopped around that date and fixes the upstream has published since may be
  missing — say that beside the date, the way the table's footnote does; the JSON document
  carries the date alone. The frozen set is readable once per `db update` from
  `assay db status --output json` (`providers[].frozen[]`).
- **State the age policy, and know what it refuses.** `--db-max-age` is judged per key: a live
  key by when its provider's data for it was current, a frozen key by its freeze (D113). On the
  2026-11-09 artifact `--db-max-age=168h` refuses every Debian 11 image (frozen since
  2026-08-19) and every Ubuntu 25.10 one (frozen since 2026-10-01) — both dates from that
  publish's D110 log lines — with a refusal that names the key and says `db update` will not
  help; it will refuse any key whose upstream stops the same way. That artifact also predates
  per-key dates, so it refuses every Amazon Linux 2 and Amazon Linux 2023 image by the provider's
  2025-03-06 (one quiet AL2 extras topic, `ansible2`) with the live-key refusal, which names the
  provider and says to run `db update` — advice that only becomes true for AL2023 on the first
  artifact built with per-key dates, and then only on a week in which AL2023's kernel-livepatch
  channel published (it dates the release along with core and nvidia; measured 2026-09-30 on
  2026-11-09, so a 168h gate still refuses AL2023 on a livepatch-quiet week). A service that
  scans end-of-support images therefore either passes the age it accepts for frozen data, or
  passes no `--db-max-age` and judges each key after the scan by `coverage[].frozenSince` where
  present and `coverage[].dataAsOf` otherwise — the gate's own rule — treating D139's seven-day
  warning (and `provenance.database.builtAt`) as its freshness alert. Pass `--db-max-rating-age`
  as well if the service promises rating freshness; `provenance.policy` records both gates in
  Go's duration spelling (`--db-max-age=168h` is recorded as `dbMaxAge: "168h0m0s"`; an unset
  gate is `null`).

Before 2026-11-09 the age gate and `coverage[].dataAsOf` read one date per provider. For a
provider that fetches several archives — OSV's one per distro family, Amazon's one per release —
that was the oldest archive's date, so every Amazon Linux 2023 scan was refused under
`--db-max-age` for one quiet Amazon Linux 2 extras topic (2025-03-06), and Debian 11's freeze was
dated by the CleanStart archive rather than Debian's. A database built before that records no
per-key dates and reads as before until the next `db update`.

## Waiving findings you have accepted

Some findings are real but not relevant to your project — the CVE is in a code path you do
not use, you have a mitigation, or you have accepted the risk. Put those in a `.assay.yaml`
in your repo (`--config <path>` names another):

```yaml
ignore:
  - vulnerability: CVE-2024-58251   # a CVE or advisory id (an alias counts)
    package: busybox                # optional: only on this package
    reason: not reachable in our build path   # required — an unexplained waiver is refused
    expires: 2026-12-31             # optional: after this date the rule stops waiving and warns
```

With no `--config`, the file is discovered in the **working directory the scan runs from**
-- not in the target -- and applied if present. When that directory is not yours (a checkout
handed to a shared runner, a service scanning what it was given), pass `--config none`: no
ignore file is applied, nothing is looked for, and the report's provenance records
`ignoreFile.path: "none"`. An empty value (`--config=`) is refused rather than read as
"discover".

A rule waives a finding only if EVERY field it names matches (`reason` is mandatory; a rule
with no match field is refused because it would waive everything). Waived findings are
**shown, never hidden**: the report counts them ("N suppressed"), names each with its
reason, and they do not trip `--fail-on` — but they stay in the output (SARIF marks them as
standard `suppressions`, which GitHub shows as dismissed). An expired rule stops waiving and
warns, so a waiver cannot outlive its justification unnoticed.

When the waiver comes from the software's *producer* rather than from you, pass their
OpenVEX document instead of transcribing it: `--vex <path>` (repeatable) applies its
`not_affected` and `fixed` statements the same way — suppressed findings are counted and
shown with the statement's own justification and author as the reason, and a statement
with no stated reason is skipped with a warning rather than honoured. `affected` and
`under_investigation` statements never suppress anything.

```sh
assay scan my-image.tar --vex vendor.openvex.json --fail-on high
```

## Why not just `--output json | jq`

You can — the JSON carries every source's rating, the per-source fixed versions, and the
skip counts, and stream discipline keeps it clean for `jq`. SARIF is the extra step that
puts findings in GitHub's Security tab as annotations a reviewer sees inline. Use whichever
your platform reads; both come from the same scan.
