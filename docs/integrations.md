# CI integration

*English · [한국어](integrations.ko.md)*

`assay scan` is built to be gated on: results go to stdout, diagnostics to stderr, and the
exit code is a contract — `0` clean, `1` a finding at or above your threshold, `2` the scan
could not run or its result cannot be trusted, with `2` outranking `1` outranking `0`. That
is all a pipeline needs.

Two complete, copy-pasteable examples:

- **[GitHub Actions](ci/github-actions.yml)** — scan on push, record findings in the
  Security tab (SARIF), fail the build on a high-or-worse finding.
- **[GitLab CI](ci/gitlab-ci.yml)** — scan in a job, keep the report as an artifact, fail
  the pipeline on the exit code.

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

The `security-events: write` permission is what lets the workflow upload to code scanning.

## The database

`assay db update` pulls the published database from `ghcr.io/kun9497/assay-db` — an OCI
artifact, seconds not hours. It is currently **private to the maintainer's namespace**, so
a job pulling it needs read access: the `docker login ghcr.io` step in both examples grants
it for a repo in the same organization (`packages: read` permission). If your pipeline
cannot reach that artifact, run `assay db build` instead — it builds the database from
upstream sources with no external artifact, at the cost of time.

The database is orthogonal to the scan: update it once per job (or cache it), and every
`assay scan` after that only reads it. A scan of an SBOM or a local tarball makes no network
call at all.

## Waiving findings you have accepted

Some findings are real but not relevant to your project — the CVE is in a code path you do
not use, you have a mitigation, or you have accepted the risk. Put those in a `.assay.yaml`
in your repo (scanned by default; `--config <path>` names another):

```yaml
ignore:
  - vulnerability: CVE-2024-58251   # a CVE or advisory id (an alias counts)
    package: busybox                # optional: only on this package
    reason: not reachable in our build path   # required — an unexplained waiver is refused
    expires: 2026-12-31             # optional: after this date the rule stops waiving and warns
```

A rule waives a finding only if EVERY field it names matches (`reason` is mandatory; a rule
with no match field is refused because it would waive everything). Waived findings are
**shown, never hidden**: the report counts them ("N suppressed"), names each with its
reason, and they do not trip `--fail-on` — but they stay in the output (SARIF marks them as
standard `suppressions`, which GitHub shows as dismissed). An expired rule stops waiving and
warns, so a waiver cannot outlive its justification unnoticed.

This is the ignore-rules half of VEX/ignore; reading a producer-signed OpenVEX document is a
separate, later capability.

## Why not just `--output json | jq`

You can — the JSON carries every source's rating, the per-source fixed versions, and the
skip counts, and stream discipline keeps it clean for `jq`. SARIF is the extra step that
puts findings in GitHub's Security tab as annotations a reviewer sees inline. Use whichever
your platform reads; both come from the same scan.
