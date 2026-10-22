# Signing the published database artifact and verifying it on pull — design (D137)

*English · [한국어](2026-10-22-artifact-signing-design.ko.md)*

Status: approved design, 2026-10-22. Implementation plan follows this document.
Decision record: roadmap D137 once merged. Supersedes the deferral "Signing and provenance
for the published database artifact" in `docs/deferred-decisions.md`, whose revisit trigger
("the moment a third party's `db update` trusts this registry by default") fired on
2026-08-28 when the package went public and `dbcmd.DefaultRef` began trusting it.

## Intent

`assay db update` pulls `ghcr.io/kun9497/assay-db:v<schema>` and installs it as the database
every scan's verdict rests on. The pull is digest-verified — the bytes match the manifest —
but nothing says *who* published the manifest. Anyone who can write that tag (a stolen
`GITHUB_TOKEN`, a registry compromise, a mirror operator) can make every customer's scanner
say "clean". The artifact must carry a signature only the project can produce, and the pull
must refuse to install anything that does not carry it.

## Decision in one paragraph

The publishing workflow signs the pushed artifact's **digest** with a project-held ECDSA
P-256 key using the cosign CLI's key-based mode; the signature lives where cosign puts it,
the `sha256-<digest>.sig` tag in the same repository. `db update` and `db build --seed`
fetch that tag through the same `go-containerregistry` path they already use, verify the
signature with the Go standard library against public keys embedded in the binary, bind the
signed payload to the pulled digest, and exit 2 on any failure. No new dependency. The
release binaries get the same key over their checksums file plus GitHub's build provenance.

## Why key-based and not keyless (measured 2026-10-22, both prototyped)

| | A: key-based, stdlib verify | B: keyless, `sigstore-go` |
|---|---|---|
| direct modules added | 0 | 2 (`sigstore-go`, `protobuf-specs`); indirect 9 → 74, `go.sum` 30 → 384 lines |
| binary | +34 KB | 7.2 MB → 20.0 MB |
| verifier | 143 lines | 139 lines plus legacy `.sig` → bundle conversion |
| verify time | 2 ms | 397 ms (TUF refresh) |
| hosts at verify | the registry only | registry + `tuf-repo-cdn.sigstore.dev` |
| offline | loud fetch error, as today | TUF cache and `WithForceCache` both fail in v1.3.0; only an embedded trusted root works |
| digest binding | the verifier's own check | the verifier's own check (the library accepts another image's genuine signature) |
| identity | a key, rotated by release | the workflow's SAN (`…/db-publish.yml@refs/heads/main`): a file rename, branch rename or repo move breaks every deployed binary |
| negative cases (wrong key/identity, tampered payload, unsigned, foreign signature, missing annotation / network cut) | 5/5 refused | 10/10 refused |

Both refuse what they should. B costs a dependency graph of 372 modules, a binary 2.8× the
size, and an identity tied to the repository's layout — which the readiness plan is about to
change (org namespace). A costs nothing the project does not already carry, and its one real
liability — a private key in a secret — is answered by rotation below.

## Goals

1. An artifact not signed by a key the binary trusts is never installed and never seeded
   from: exit 2, a message that says *unsigned* or *signature does not verify*, never a
   silent fall-through.
2. The signature binds the exact manifest digest, so a genuine signature moved to another
   artifact is refused.
3. Zero new direct dependencies; the scan path is untouched (it never reaches the registry).
4. Rotation without a flag day: the binary trusts a list of keys; a new key enters a release
   before it signs anything, the old key leaves after a stated window.
5. `db status` and the scan's provenance say what verified the installed database.
6. Nothing in the nightly can push an unsigned artifact unnoticed.

## Non-goals

- Keyless / Sigstore identity, Rekor transparency, SLSA for the *database* artifact. The
  release binaries get GitHub's build provenance attestation because it is one action and no
  code; the database does not, this round.
- Signing scan reports / attestations (D120's record). Same key, later decision.
- Encrypting the artifact. It is public.
- A trust policy file on the customer side. The trusted keys are the binary's.

## Anti-goals (what would make this a failure even if it works)

- A verification that can be skipped by accident: a missing `.sig` tag read as "nothing to
  verify", a mirror that dropped the tag passing quietly, a flag that is on by default.
- A key rotation that bricks deployed scanners (every `db update` failing until a release).
- Verification code large enough that a wrong answer hides in it. The spike's 143 lines is
  the budget.

## Constraints

- Five direct dependencies (CLAUDE.md); `CGO_ENABLED=0`.
- D14: a scan never fetches. Verification lives in `db update` / `db build --seed` only.
- D11/D16 shape: an untrustworthy input is exit 2 at the boundary, never installed.
- D127: the artifact record lives inside `Meta`, written before the rename; what verified it
  belongs there too.
- D60/D65 guards and the D114 gate are unchanged; signing is after `db push`, outside them.

## The design

### Keys

- One ECDSA P-256 key pair per signing identity, generated with `cosign generate-key-pair`.
  Private key and its password: GitHub repository secrets `COSIGN_PRIVATE_KEY`,
  `COSIGN_PASSWORD`. Public key: committed at `internal/dbcmd/trust/keys/<id>.pub` (PEM,
  PKIX) and embedded with `go:embed`.
- A key's **id** is the lowercase hex SHA-256 of its DER (PKIX) bytes, first 16 characters —
  what cosign prints and what error messages and `db status` name.
- The binary trusts every key under `trust/keys/`, in file order. One is enough; two during
  a rotation.
- Rotation: (1) commit the new public key, release; (2) after that release has shipped,
  switch the secret and sign with the new key; (3) one release later, delete the old public
  key. Each step is a PR; the window is at least one release. A compromised key is the same
  sequence compressed: a release that removes the key, then re-sign the current artifact with
  the new one by `workflow_dispatch`.

### Signing (workflows)

- `db-publish.yml` and `db-backfill.yml`, after their `db push` step: install cosign with
  `sigstore/cosign-installer` **pinned by commit SHA**, read the pushed digest from `db push`'s
  stdout (it already prints `ghcr.io/kun9497/assay-db@sha256:…`), and run
  `cosign sign --key env://COSIGN_PRIVATE_KEY --tlog-upload=false --yes <ref>@sha256:<digest>`.
  By digest, never by tag: the `.sig` tag is derived from the digest, and signing a tag races
  the next push. `--tlog-upload=false` because verification does not consult Rekor and a
  Rekor outage must not fail a publish.
- A self-check step follows: `cosign verify --key <the committed .pub> --insecure-ignore-tlog
  <ref>@sha256:<digest>` must exit 0, or the job fails loudly after the push (the artifact
  is then live but unsigned, and the next step below is why that is visible).
- `db push` learns nothing about signing. The push guard is unchanged.
- The D28 schema-bump bootstrap (hand-run `db push`) is documented in the README runbook as
  "push, then sign by digest with the same two commands"; a bootstrap that forgets is caught
  by the first `db update` against the new tag.

### Verification (`internal/dbcmd`)

New package `internal/dbcmd/trust` (name is the builder's call), ~120 lines, stdlib + ggcr:

```
func Verify(ctx, repo name.Repository, digest v1.Hash, keys []PublicKey, opts ...remote.Option) (keyID string, err error)
```

1. Fetch the manifest at tag `sha256-<hex>.sig` with the **same** `remote` options the pull
   used (auth, context; `remote.Reuse` so the `/v2/` ping is not repeated). A
   `MANIFEST_UNKNOWN` is reported as *"the artifact at <ref>@<digest> is not signed"* — a
   distinct error from a transport failure.
2. For each layer, in order: read the layer's bytes with a **64 KiB cap** (the tag is
   attacker-writable in the threat model); read the annotation
   `dev.cosignproject.cosign/signature` (base64 DER ECDSA); for each trusted key,
   `ecdsa.VerifyASN1(pub, sha256(rawPayload), sig)`. Only after a key verifies the raw bytes:
   `json.Unmarshal` the payload and require `critical.type == "cosign container image
   signature"` and `critical.image["docker-manifest-digest"] == digest.String()`.
3. The first layer that passes every check accepts, returning the key id. Otherwise the
   error lists every layer's reason (cosign appends layers on re-sign; the diagnostics must
   name them all).
4. Nothing else is read from the payload. `optional`, `docker-reference` and the rest are
   ignored — the reference a mirror serves differs from the one signed, by design.

Call sites:

- `Pull` (`db update`): after `MetaOf`'s schema check (a mismatch still costs one request)
  and **before `Unpack`** (an unsigned artifact never reaches the temp file). On error:
  exit 2 with the message; the installed database is untouched.
- `PullSeed` (`db build --seed`): the same call, same failure. A seed is trust input for the
  whole carry-forward (D66/D110); it must be verified like an install.
- `--from <ref>` (a customer mirror, D28): verified exactly the same way. A mirror that did
  not copy the `.sig` tag fails with the *not signed* message, which names the tag so the
  operator can copy it. One escape hatch, explicit: `--allow-unsigned` on `db update`
  prints a warning, installs, and records the fact (next item). It is never implied by
  `--from`.

Record, `db status`, provenance:

- `store.ArtifactRecord` (D127) gains `SignedBy string` (the key id) or `Unverified bool`.
  `db status` prints `signed:     key <id>` or `signed:     NO (--allow-unsigned)`. The
  scan's D120 `provenance.database.artifact` carries the same two fields, so a report says
  whether the database behind its verdict was verified.
- A database built locally has neither (it was never pulled), as today.

### Release binaries

- `.goreleaser.yaml`: `signs:` with cosign over the checksums file using the same key
  (`COSIGN_PRIVATE_KEY`/`COSIGN_PASSWORD` in `release.yml`); publish `…_checksums.txt.sig`
  and `.pem`-free (key-based) verification instructions in the README.
- `release.yml`: `actions/attest-build-provenance` (pinned by SHA) over the archives —
  GitHub-native SLSA provenance, `id-token: write`, no code.
- `install.sh`: the pinned-script shape, decided 2026-10-22 after both shapes were built
  and attacked (below).

### The installer: pinned script, embedded keys (decided)

Two shapes were prototyped against one attack matrix (clean install; archive tampered;
release assets rewritten consistently with a stale or missing `.sig`; the repository tree
compromised and every fetchable key replaced; `.sig` absent; no `cosign` on the host; key
rotation; `latest` resolution; tag mutability). What separated them:

- A script that fetches its public key from the repository tree at the tag verifies nothing
  a repository compromise cannot forge: the attacker re-signs with their key and replaces the
  fetched key, and the script prints "signature verified" over their build. It also, as
  built, warned on a missing `.sig` — so deleting the `.sig` was a free downgrade.
- A script that **embeds** the keys refuses that attack as long as the bytes the user runs
  are genuine. A tag URL does not guarantee that: `git tag -f` moves it and
  `raw.githubusercontent.com` re-serves the moved tag within its 5-minute cache. A
  **commit-SHA URL is immutable**.
- `api.github.com/repos/…/releases/latest` was rate-limited (403, 60/h) from the test
  machine at the moment of the test; the `github.com/…/releases/latest` 302 redirect
  resolved the tag unauthenticated. Today's installer fails under that limit.
- `openssl dgst -sha256 -verify <pub> -signature <der> <file>` verifies cosign's
  `sign-blob` output directly (genuine OK; tampered file and wrong key fail), so the
  installer does not need `cosign` on the host.

Therefore:

1. The README one-liner pins the **release commit SHA**:
   `curl -sSfL https://raw.githubusercontent.com/kun9497/assay/<sha>/install.sh | sh`. The
   release job rewrites that line (and the KO README) as part of cutting the release, so the
   documented line always names the commit the release was built from. A tag may be given as
   a convenience in prose, never as the one-liner.
2. The script embeds the trusted public key(s) as PEM heredocs and installs **its own
   version** by default; an explicit `<version>` argument installs another release, still
   verified against the embedded keys. There is no `latest` lookup and no `api.github.com`
   call. (If a `latest` convenience is ever wanted it reads the `/releases/latest`
   `Location` header, never the API.)
3. It downloads the archive, the checksums file and `…_checksums.txt.sig`, and verifies the
   signature with **openssl** when present, else `cosign verify-blob`, else refuses with a
   message naming `ASSAY_ALLOW_UNSIGNED=1`, which degrades to today's checksum-only install
   with a loud warning. A missing `.sig` is **refused**, never warned about: every release
   from the first signed one on attaches it, and `release.yml` fails hard if signing fails
   rather than publishing without it.
4. The sha256 check stays unconditional, after the signature.
5. Rotation: release N+1's script embeds keys N and N+1; a script pinned at N refuses N+1's
   release with a hint to run the installer published with that release. Users who copied the
   one-liner into CI bump the SHA at rotation — the documented cost of a trust root that
   travels with the script.
6. Windows stays out of scope for the script (zips are published; the README points at them).

### Rollout order (the flag-day hazard)

A verifying binary that runs before the published artifact is signed makes every pull fail —
and three workflows build assay from `main` and pull before any release: `db-publish.yml`
and `db-backfill.yml` seed through `PullSeed`, `scanner-diff.yml` runs `db update`. So the
verification **call sites** are a separate PR from the signing, and nothing is gated on a
key list being empty:

1. PR 1: public key committed under `trust/keys/`; `db-publish.yml`, `db-backfill.yml` and
   the new `db-sign.yml` sign after push and self-verify; the `trust` package with its unit
   tests; the record fields and `db status` line. **No call site in `Pull`/`PullSeed` yet.**
2. The next nightly pushes and signs. Confirm `sha256-<digest>.sig` exists on `:v<schema>`
   and the self-check passed. If the nightly is not due, dispatch `db-sign.yml` with the
   current digest so the *current* tag is signed before step 3.
3. PR 2: the call sites in `Pull` and `PullSeed`, their caller tests, the mutation round.
   From its merge every workflow build verifies; the nightly's own seed step is the first
   production check.
4. Release v0.12.0. The weekly differential, which builds from `main` and pulls anonymously,
   is the standing end-to-end check that the artifact customers get is signed.

### Signing outside the nightly: `db-sign.yml`

A `workflow_dispatch` workflow with one input, `digest` (`sha256:…`), that signs
`ghcr.io/kun9497/assay-db@<digest>` with the repository secret and runs the self-check. It
is the only way a signature is produced outside the two publishing workflows, and it serves
three runbooks: the D28 schema-bump bootstrap (a human pushes `:vN` by hand, then dispatches
this with the printed digest — the human never holds the key; the runbook is
`docs/DESIGN.md`'s bootstrap section, not the README); the compromise response (new key
committed and released, secret rotated, dispatch once for the current digest); and D110
recovery seeds (below).

### Seeds that predate signing

`db build --seed` verifies exactly like `db update` and has **no escape hatch**. An artifact
that predates signing — a D110 recovery snapshot named by digest, the previous schema's tag
`PullSeed` falls back to, a mirror's copy — is made usable by signing its digest with
`db-sign.yml` first, which takes a minute and leaves a signature anyone can check. The D110
recovery runbook gains that one step. A seed is the trust root of a whole carry-forward; a
flag that let an unsigned one in would be the anti-goal above. (`--allow-unsigned` stays a
`db update` flag only, and is recorded when used.)

### cosign version

The spike and this design use cosign's **legacy signature layout** (`sha256-<digest>.sig`
tag, simple-signing payload, `dev.cosignproject.cosign/signature` annotation), which is what
cosign **v2.x** writes by default. cosign v3.0.0 (2025-10-07) defaults `sign` to the
protobuf bundle stored as an OCI 1.1 referrer — nothing lands at the `.sig` tag, and the
verifier here would report every nightly as unsigned while a v3 `cosign verify` passed. So
the installer is pinned to the **v2.4 line** (SHA-pinned `cosign-installer` with
`cosign-release: v2.4.3`), and the self-check runs the same pinned binary with `--key …
--insecure-ignore-tlog`, which reads the same tag the Go verifier reads. Moving to the
referrer/bundle format is a later decision with its own verifier; it is not this one.

## Verification plan (tests)

- In-process registry: ggcr's `pkg/registry` (already in the module graph) over `httptest`.
  Signatures minted **in-test** with `crypto/ecdsa` in cosign's payload shape; the cosign CLI
  is never needed at test time. One opt-in test (`ASSAY_COSIGN=path`) signs with the real CLI
  to pin format compatibility, skipped otherwise.
- Caller first (CLAUDE.md): `Pull` against a signed artifact installs and records the key
  id; against an unsigned one exits 2 *before* the temp file exists; deleting the `Verify`
  call in `Pull` turns that test red. Same for `PullSeed`.
- Table, each row executed: wrong key; tampered payload (re-serialised JSON naming the right
  digest); no `.sig` tag; a genuine signature for another digest; missing annotation; two
  layers where only the second is valid; a payload over the cap; two trusted keys where only
  the second signs; `--allow-unsigned` installs with the record saying so and without it the
  same artifact is refused.
- Mutations to run before calling it done: verify-after-parse instead of before; digest
  check removed; type check removed; cap removed; first-layer-only; `MANIFEST_UNKNOWN`
  treated as success; `--allow-unsigned` implied by `--from`; key list empty accepting.
- Workflow: the self-check step is the test of the signing step; a deliberately wrong key in
  a dry run must fail it.

## Measured numbers to cite (spike A, 2026-10-22)

0 modules, +34,304 bytes, 143 lines, 2 ms, 3 registry requests for the signature (2 with a
reused transport), 5/5 negatives refused, offline = `dial tcp … refused` at resolve, exit 2.

## Left to the builder

- Package and flag names; whether `SignedBy`/`Unverified` are one field or two.
- Exact error wording, within the rule that *unsigned*, *does not verify* and *transport
  failure* are three different sentences.
- The README/integrations wording for mirrors (`--from`) and for `--allow-unsigned`.
- Whether `db push` should print the digest on its own line for the workflow to capture (it
  prints `ref@digest` today; a `--print-digest` is fine if cleaner).

## Open questions settled here

- *What if Rekor is down?* Irrelevant: `--tlog-upload=false`, verification never asks.
- *What about air-gapped customers?* They mirror the artifact and its `.sig` tag (two tags,
  `crane copy` does both with `--all-tags`) and pull with `--from`; verification runs against
  their mirror. `--allow-unsigned` exists for a mirror that cannot carry the tag, and leaves
  a mark.
- *Does the key in a secret make GitHub the trust root?* Yes, as it already is for the
  `GITHUB_TOKEN` that pushes. The gain is that a token theft no longer suffices: the signing
  key is a second secret with a different lifecycle, and its public half is pinned in every
  customer's binary.
