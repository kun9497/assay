# D137 Artifact Signing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The published database artifact is signed by a project key after every push, and `db update` / `db build --seed` refuse anything not signed by a key embedded in the binary; release binaries and the installer get the same key.

**Architecture:** Signing is workflow-only (cosign v2.4 CLI, key in a repository secret). Verification is a ~120-line package `internal/dbcmd/trust` using `crypto/ecdsa` + go-containerregistry `remote` to fetch cosign's `sha256-<digest>.sig` tag; `Pull`/`PullSeed` call it before unpacking. Two PRs, because three workflows build from `main` and pull: PR 1 ships signing + the package + records; PR 2 wires the call sites after the first signed nightly.

**Tech Stack:** Go 1.26 stdlib (`crypto/ecdsa`, `crypto/sha256`, `crypto/x509`, `encoding/pem`), go-containerregistry v0.21.7 (`pkg/name`, `pkg/v1`, `pkg/v1/remote`, `pkg/registry` in tests), cosign v2.4.3 CLI in GitHub Actions only, POSIX sh + openssl for the installer.

**Spec:** `docs/superpowers/specs/2026-10-22-artifact-signing-design.md` (KO: `.ko.md`)

## Global Constraints

- Zero new direct dependencies in `go.mod`; `CGO_ENABLED=0`; `GOFLAGS=-mod=readonly` for every verification run.
- The scan path never touches the registry (D14): nothing in `internal/scancmd` or `internal/matcher` changes.
- Any verification failure is exit 2 with one of three distinct messages: *not signed*, *does not verify*, *transport failure*. Never a silent fall-through, never a default-on skip.
- Signing is by **digest**, never by tag; cosign is the **v2.4 line** (`cosign-release: v2.4.3`), `--tlog-upload=false`, legacy `.sig` tag layout.
- Payload read cap 65536 bytes; `ecdsa.VerifyASN1` over `sha256(raw payload bytes)` **before** `json.Unmarshal`; `critical.type == "cosign container image signature"`; `critical.image["docker-manifest-digest"] == digest`.
- Key id = first 16 hex chars of `sha256(PKIX DER)`.
- Every GitHub Action introduced is pinned by commit SHA with the version in a trailing comment.
- Bilingual docs in the same commit (roadmap, DESIGN, deferred-decisions, README); plans are English-only.
- Commit before any mutation round; `git checkout -- <file>` restores to HEAD (CLAUDE.md).
- Rollout: the `Pull`/`PullSeed` call sites (Task 9) are merged only after a signed artifact exists on the current `:v<schema>` tag.

## Review Focus

1. A `.sig` tag whose manifest has **two layers** where only the second verifies (cosign appends on re-sign): accept, and the error on total failure names both layers — Task 2.
2. A registry that answers the `.sig` manifest with a **401/403** (private mirror, auth not carried to the second fetch): the message must be the *transport* one naming the status, not "not signed" — Task 2.
3. A payload layer **larger than the cap** or **not JSON**: refused as "does not verify", never read whole — Task 2.
4. `--allow-unsigned` given with the **default** ref (no `--from`): still honoured, warning printed, record marked — a user may want it in an outage; but it must never be implied — Task 9.
5. `install.sh` run on a host with **neither openssl nor cosign** and no opt-out: exit 1 before any download is extracted — Task 7.

---

## PR 1 — sign, verify-capable, record (branch `feat/d137-signing`)

### Task 1: The key pair and the embedded trust list

**Files:**
- Create: `internal/dbcmd/trust/keys/<id>.pub` (PEM, PKIX, ECDSA P-256)
- Create: `internal/dbcmd/trust/keys.go` (embed + parse)
- Test: `internal/dbcmd/trust/keys_test.go`

**Interfaces:**
- Produces: `package trust`; `type PublicKey struct { ID string; Key *ecdsa.PublicKey }`; `func TrustedKeys() []PublicKey` (parsed from the embedded FS at init, panics on a malformed committed key — a build-time defect, not a runtime one); `func ParsePublicKeyPEM(pem []byte) (PublicKey, error)`; `func KeyID(pub *ecdsa.PublicKey) string`.

- [ ] **Step 1: Generate the key pair OUTSIDE the repository** (the human does this once; the plan records it): `cosign generate-key-pair` in `~/assay-signing/` with a password; `cosign.pub` is copied into the repo, `cosign.key` + password go to repository secrets `COSIGN_PRIVATE_KEY` / `COSIGN_PASSWORD` via `gh secret set`. The private key is never read by anything in this plan.

- [ ] **Step 2: Write the failing tests** in `keys_test.go`:
  - `TestTrustedKeys_EmbedsAtLeastOneP256Key`: `len(TrustedKeys()) >= 1`, every `Key.Curve == elliptic.P256()`, every `ID` is 16 lowercase hex chars.
  - `TestKeyID_IsSHA256OfPKIXDER`: generate a key with `ecdsa.GenerateKey`, compute `sha256(x509.MarshalPKIXPublicKey)` yourself, assert `KeyID` equals its first 16 hex chars.
  - `TestParsePublicKeyPEM_RejectsRSAAndGarbage`: an RSA PEM and `[]byte("nope")` both return an error.

- [ ] **Step 3: Run** `go test ./internal/dbcmd/trust -run 'TestTrustedKeys|TestKeyID|TestParse' -count=1` — FAIL (package missing).

- [ ] **Step 4: Implement `keys.go`**: `//go:embed keys/*.pub` into an `embed.FS`; `TrustedKeys` reads entries in name order; `ParsePublicKeyPEM` decodes PEM → `x509.ParsePKIXPublicKey` → asserts `*ecdsa.PublicKey` with P-256.

- [ ] **Step 5: Run** the same command — PASS. `gofmt -l internal/dbcmd/trust` empty.

- [ ] **Step 6: Commit** `feat(trust): the embedded public key list and its id (D137)`.

### Task 2: `trust.Verify` against an in-process registry

**Files:**
- Create: `internal/dbcmd/trust/verify.go`
- Test: `internal/dbcmd/trust/verify_test.go`, `internal/dbcmd/trust/sigtest_test.go` (helpers)

**Interfaces:**
- Consumes: Task 1's `PublicKey`, `TrustedKeys`.
- Produces: `func SigTag(digest v1.Hash) string` (returns `sha256-<hex>.sig`); `func Verify(ctx context.Context, repo name.Repository, digest v1.Hash, keys []PublicKey, opts ...remote.Option) (keyID string, err error)`; sentinel `var ErrNotSigned = errors.New("artifact is not signed")` (wrapped with the ref and tag name) and `var ErrNoKeyVerifies = errors.New("no signature verified under a trusted key")`; a transport failure is returned unwrapped by either sentinel. Constants `MaxPayloadBytes = 65536`, `SignatureAnnotation = "dev.cosignproject.cosign/signature"`, `PayloadType = "cosign container image signature"`.

- [ ] **Step 1: Write the test helpers** in `sigtest_test.go`: `newRegistry(t) (host string)` (ggcr `registry.New()` over `httptest`); `pushArtifact(t, host, tag string) (name.Reference, v1.Hash)` (a one-layer random image via `remote.Write`); `signTestPayload(t, key *ecdsa.PrivateKey, digest v1.Hash) (payload []byte, sigB64 string)` building cosign's simple-signing JSON `{"critical":{"identity":{"docker-reference":"<repo>"},"image":{"docker-manifest-digest":"<digest>"},"type":"cosign container image signature"},"optional":null}` and `ecdsa.SignASN1(sha256(payload))`; `writeSig(t, host, repo string, digest v1.Hash, layers []sigLayer)` writing an image whose layers are the payloads with the annotation set (or omitted when `sigLayer.noAnnotation`) to the `SigTag(digest)` tag.

- [ ] **Step 2: Write the failing tests** in `verify_test.go` (each row executed, assertions as stated):
  - `TestVerify_AcceptsAGenuineSignatureAndReportsTheKey`: one key, one layer → `keyID == KeyID(pub)`, `err == nil`.
  - `TestVerify_WrongKeyIsRefused`: signed with key A, trusted key B → `errors.Is(err, ErrNoKeyVerifies)`.
  - `TestVerify_TamperedPayloadIsRefusedBeforeParsing`: payload re-serialised with `"optional":{"x":1}` (still names the right digest), original signature → `ErrNoKeyVerifies`.
  - `TestVerify_UnsignedArtifactIsNotSigned`: no `.sig` tag → `errors.Is(err, ErrNotSigned)` and the message contains `SigTag(digest)`.
  - `TestVerify_ForeignGenuineSignatureIsRefusedOnDigest`: a genuine signature for digest B written to A's sig tag → error mentions both digests, not `ErrNotSigned`.
  - `TestVerify_MissingAnnotationIsRefused`: layer without the annotation → `ErrNoKeyVerifies`, message contains `SignatureAnnotation`.
  - `TestVerify_SecondLayerAloneCanAccept`: layers [bad, good] → accepted; `TestVerify_AllLayersNamedOnFailure`: layers [bad, bad] → message contains `layer 0` and `layer 1`.
  - `TestVerify_PayloadOverCapIsRefusedWithoutReading`: a 70 KB layer → `ErrNoKeyVerifies`; assert the registry saw no blob GET larger than… simply assert the error mentions `MaxPayloadBytes`.
  - `TestVerify_TwoTrustedKeysSecondSigns`: keys [A, B], signed by B → accepted with B's id.
  - `TestVerify_WrongPayloadTypeIsRefused`: `critical.type` changed, re-signed with the trusted key → refused on type.
  - `TestVerify_TransportFailureIsNotNotSigned`: registry wrapper returns 403 on the sig manifest → err is neither sentinel and contains `403`.
  - `TestVerify_EmptyKeyListRefuses`: `keys == nil` → `ErrNoKeyVerifies` even for a genuine signature.

- [ ] **Step 3: Run** `go test ./internal/dbcmd/trust -count=1` — FAIL (Verify undefined).

- [ ] **Step 4: Implement `verify.go`** per the spec's four numbered rules: `remote.Image(repo.Tag(SigTag(digest)), opts...)`; a `transport.Error` with `MANIFEST_UNKNOWN` → `ErrNotSigned`; iterate `img.Layers()`; `io.LimitReader(rc, MaxPayloadBytes+1)` and refuse when more than the cap is read; annotation from the manifest's layer descriptor; `base64.StdEncoding`; verify over raw bytes per key; then parse and check type + digest; collect per-layer reasons.

- [ ] **Step 5: Run** `go test ./internal/dbcmd/trust -count=1` — PASS; `go vet ./internal/dbcmd/trust` clean.

- [ ] **Step 6: Commit** `feat(trust): Verify fetches cosign's .sig tag and verifies it with the stdlib (D137)`.

- [ ] **Step 7: Mutation round (after the commit)**, each must turn the package red; record the result in the commit message of Task 10's docs: verify after parse; digest check removed; type check removed; cap removed; first-layer-only; `MANIFEST_UNKNOWN` returned as success; wrong-key loop breaking on the first key.

### Task 3: The artifact record says what verified it

**Files:**
- Modify: `internal/store/artifact.go` (`ArtifactRecord`)
- Modify: `internal/dbcmd/dbcmd.go:866-867` (`db status`)
- Modify: `internal/report/provenance.go:85-88,120-122` (`ArtifactProvenance`, `NewDatabaseProvenance`)
- Test: `internal/dbcmd/artifact_record_test.go`, `internal/report/provenance_test.go`

**Interfaces:**
- Produces: `ArtifactRecord.SignedBy string \`json:"signedBy,omitempty"\`` (a key id) and `ArtifactRecord.Unverified bool \`json:"unverified,omitempty"\``; `ArtifactProvenance.SignedBy string \`json:"signedBy,omitempty"\``, `ArtifactProvenance.Unverified bool \`json:"unverified,omitempty"\``. `db status` line after `pulled:`: `signed:     key <id>` when `SignedBy != ""`, `signed:     NO (--allow-unsigned)` when `Unverified`, no line otherwise.

- [ ] **Step 1: Write the failing tests**: in `artifact_record_test.go` add `TestStatus_PrintsTheSigningKey` (SetArtifact with `SignedBy: "0123456789abcdef"` → stdout contains `signed:     key 0123456789abcdef`) and `TestStatus_PrintsUnverified` (`Unverified: true` → contains `signed:     NO (--allow-unsigned)`), and extend the existing built-database assertion to also refuse `signed:`. In `provenance_test.go` add `TestNewDatabaseProvenance_CarriesSignedByAndUnverified` asserting both fields round-trip through `json.Marshal` and are omitted when zero.

- [ ] **Step 2: Run** `go test ./internal/dbcmd -run TestStatus_ -count=1 && go test ./internal/report -run TestNewDatabaseProvenance_Carries -count=1` — FAIL (fields undefined).

- [ ] **Step 3: Implement** the two struct fields, the status lines, and the copy in `NewDatabaseProvenance`.

- [ ] **Step 4: Run** the same — PASS; `go test ./internal/store ./internal/dbcmd ./internal/report -count=1` still green (JSON additive, omitempty).

- [ ] **Step 5: Commit** `feat(store,dbcmd,report): the artifact record names the key that verified it, or that none did (D137)`.

### Task 4: Signing in the publishing workflows, and `db-sign.yml`

**Files:**
- Modify: `.github/workflows/db-publish.yml` (after the `Publish` step at line ~215)
- Modify: `.github/workflows/db-backfill.yml` (after its `Publish` step)
- Create: `.github/workflows/db-sign.yml`
- Modify: `.github/actions/setup-scanners/action.yml` — no; create `.github/actions/setup-cosign/action.yml` (one composite used by all three)

**Interfaces:**
- Produces: composite `setup-cosign` running `sigstore/cosign-installer@<sha> # v3.x` with `cosign-release: v2.4.3`; the sign step shape `cosign sign --key env://COSIGN_PRIVATE_KEY --tlog-upload=false --yes "$REF@$DIGEST"` followed by `cosign verify --key internal/dbcmd/trust/keys/<id>.pub --insecure-ignore-tlog "$REF@$DIGEST"` looping over every `keys/*.pub` until one passes.

- [ ] **Step 1: Make `db push` emit the digest on its own line**: in `internal/dbcmd/push.go` after `remote.Write`, print `pushed <ref>@<digest>` to stderr and the bare `<ref>@<digest>` to stdout (it already prints the latter; confirm with `TestPush_PrintsTheDigestAlone` in `push_test.go` asserting stdout's last line matches `^.+@sha256:[0-9a-f]{64}$`). Run, PASS, commit `feat(dbcmd): db push prints the pushed digest alone on stdout`.

- [ ] **Step 2: Resolve the action SHA**: `gh api repos/sigstore/cosign-installer/git/ref/tags/v3.7.0 --jq .object.sha` (or the newest v3 tag); write it into the composite with the version as a comment.

- [ ] **Step 3: Write the composite and the three workflow changes.** `db-publish.yml`/`db-backfill.yml`: capture `db push` stdout into `steps.push.outputs.digest` (`echo "digest=$(./bin/assay db push … | tail -n1)" >> "$GITHUB_OUTPUT"`), then `uses: ./.github/actions/setup-cosign`, then the sign step, then the self-check step, both with `env: COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}`, `COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}`. `db-sign.yml`: `workflow_dispatch` input `digest` (required, pattern `^sha256:[0-9a-f]{64}$` checked in a step), `permissions: packages: write`, login, setup-cosign, sign `ghcr.io/kun9497/assay-db@${{ inputs.digest }}`, self-check.

- [ ] **Step 4: Verify locally what can be**: `actionlint` if available, else `python -c "import yaml"` parse of each file; `gh workflow view db-sign.yml` after push shows the input.

- [ ] **Step 5: Commit** `ci: sign the pushed artifact by digest with cosign v2.4 and self-verify; db-sign.yml signs any digest (D137)`.

### Task 5: Release signing and provenance

**Files:**
- Modify: `.goreleaser.yaml` (`signs:` block)
- Modify: `.github/workflows/release.yml` (permissions, setup-cosign, attestation, README pin commit)

**Interfaces:**
- Produces: release assets `assay_<ver>_checksums.txt.sig` (cosign `sign-blob --key env://COSIGN_PRIVATE_KEY --tlog-upload=false --output-signature`); an `actions/attest-build-provenance@<sha>` attestation over `dist/*.tar.gz`, `dist/*.zip`; a commit on `main` after the release rewriting the README one-liner (Task 7's line) to the tagged commit's SHA.

- [ ] **Step 1: `.goreleaser.yaml`**: add `signs: - cmd: cosign; artifacts: checksum; args: ["sign-blob", "--key", "env://COSIGN_PRIVATE_KEY", "--tlog-upload=false", "--yes", "--output-signature", "${signature}", "${artifact}"]; signature: "${artifact}.sig"`. Remove the `before: go mod tidy` hook (a release must build the committed `go.mod`; CI already tests it).

- [ ] **Step 2: `release.yml`**: `permissions: contents: write, id-token: write, attestations: write`; steps: setup-cosign; goreleaser with the two cosign secrets in `env`; `actions/attest-build-provenance@<sha>` with `subject-path: dist/*.tar.gz dist/*.zip`; a final step that checks out `main`, runs `sed` to replace the SHA in the README one-liner (EN and KO) with `${{ github.sha }}`, and commits with the message `docs: pin the install one-liner to <tag> (<sha>)` — guarded with `if: github.ref_type == 'tag'`.

- [ ] **Step 3: Verify**: `goreleaser check` locally if installed; YAML parse; a dry `goreleaser release --snapshot --clean --skip=sign,publish` if available.

- [ ] **Step 4: Commit** `ci(release): sign the checksums with the project key, attest build provenance, pin the README one-liner to the release commit (D137)`.

### Task 6: README, DESIGN runbook, deferred entry (PR 1 docs)

**Files:**
- Modify: `README.md:26`, `README.ko.md:26` (one-liner by commit SHA; verification wording)
- Modify: `docs/DESIGN.md` bootstrap section (~393-425) and `.ko.md`: "push, then dispatch `db-sign.yml` with the printed digest"; D110 recovery runbook gains the same step
- Modify: `docs/deferred-decisions.md` + `.ko.md`: strike the signing entry's title `~~…~~ — resolved in D137 (2026-10-22)`, keep the body, add two lines on what was decided and the installer measurement

- [ ] **Step 1: Edit** all six files; the README one-liner becomes `curl -sSfL https://raw.githubusercontent.com/kun9497/assay/<sha>/install.sh | sudo sh -s -- -b /usr/local/bin` with `<sha>` = the current `main` HEAD until the release job rewrites it, and a sentence: "The script embeds the project's signing key and verifies the release's checksums signature with openssl (or cosign) before the checksum; pin a different release with `-s -- vX.Y.Z`."

- [ ] **Step 2: Verify** both READMEs still parse (`python -I -c` CRLF/KELVIN check as the project does) and the KO lines mirror the EN ones.

- [ ] **Step 3: Commit** `docs: D137 runbooks — sign after a hand push, sign a recovery seed, installer one-liner by commit (EN/KO)`.

### Task 7: `install.sh` — pinned script, embedded keys, openssl verification

**Files:**
- Modify: `install.sh` (rewrite; keep POSIX sh, curl/wget, tar, sha256sum/shasum)
- Create: `scripts/install_test.sh` (the fixture harness) and `scripts/install_fixture.py` (serves `releases/download/<tag>/…`)
- Modify: `.github/workflows/ci.yml` (one step running the harness)

**Interfaces:**
- Produces: `install.sh` constants `VERSION="vX.Y.Z"` (rewritten by the release job via `sed` on the line `^VERSION=`), `TRUSTED_KEYS` heredoc(s) of the PEMs in `internal/dbcmd/trust/keys/`; env overrides `ASSAY_RELEASE_BASE` (default `https://github.com/kun9497/assay/releases/download`), `ASSAY_ALLOW_UNSIGNED=1`; exit 1 messages exactly: `assay: <sums>.sig is missing from the <ver> release — refusing to install an unsigned checksums file`, `assay: signature on <sums> does not verify against any key embedded in this installer (<ver>) — refusing to install`, `assay: neither openssl nor cosign is available to verify <sums>.sig — refusing to install (set ASSAY_ALLOW_UNSIGNED=1 to accept the sha256 check alone)`.

- [ ] **Step 1: Write the harness first** (`scripts/install_test.sh`): builds a fake release tree in a temp dir (tiny `assay` script archives for the current OS/arch, GoReleaser-format checksums with two spaces, `.sig` made with `openssl dgst -sha256 -sign <test key>` — **openssl, not cosign**, so CI needs nothing installed; the DER output is base64-encoded like cosign's), serves it with `python3 -m http.server`, and runs these cases asserting exit codes and the message substrings above: C1 clean (0); C2 archive tampered (1, `checksum mismatch`); C3a assets rewritten + stale sig (1, `does not verify`); C3a-nosig (1, `is missing`); C5 no openssl/cosign on PATH (1, `neither openssl nor cosign`); C5-allow with `ASSAY_ALLOW_UNSIGNED=1` (0, stderr has `WARNING`); C5-allow + C2 tree (1, `checksum mismatch`); C6 a second key: script with [key1,key2] installs a release signed by key2 (0), script with [key1] refuses it (1).

- [ ] **Step 2: Run** `sh scripts/install_test.sh` against the current `install.sh` — FAIL on C3a/C3a-nosig/C5 (today's script installs or ignores).

- [ ] **Step 3: Rewrite `install.sh`**: drop the `latest`/api.github.com block; `VERSION` constant; `<version>` argument still accepted; download archive, `<sums>`, `<sums>.sig`; verify: `openssl dgst -sha256 -verify <keyfile> -signature <der>` after `base64 -d` (fallback `cosign verify-blob --key <keyfile> --signature <sig> --insecure-ignore-tlog`), looping over the embedded keys; then the existing sha256 block unchanged; then extract. Keys are written to temp files from the heredocs.

- [ ] **Step 4: Run** `sh scripts/install_test.sh` — all cases PASS; `shellcheck install.sh` if available.

- [ ] **Step 5: CI**: add `- run: sh scripts/install_test.sh` to `ci.yml` after the build step (ubuntu has openssl and python3).

- [ ] **Step 6: Commit** `feat(install): the installer pins its own version, embeds the signing keys and verifies the checksums signature with openssl (D137)`.

### Task 8: PR 1 review and merge gate

- [ ] **Step 1:** `gofmt -l cmd internal` empty; `go vet ./...`; `go test ./...` green; the Task 2 mutation table complete.
- [ ] **Step 2:** Open PR 1 with the spec linked; the two-lens adversarial review workflow as for PR #179; fold findings.
- [ ] **Step 3 (human):** set the two secrets; merge; watch the next nightly: the `Publish` step's digest, the sign and self-check steps green, `sha256-<digest>.sig` present on `:v<schema>` (`gh api` or `crane manifest`). If the nightly is not due, dispatch `db-sign.yml` with the current digest. **Task 9 waits for this.**

---

## PR 2 — the call sites (branch `feat/d137-verify-on-pull`, after Task 8 Step 3)

### Task 9: `Pull` and `PullSeed` verify; `--allow-unsigned`

**Files:**
- Modify: `internal/dbcmd/pull.go` (`Pull` signature gains `allowUnsigned bool`; `PullSeed` unchanged signature)
- Modify: `cmd/assay/main.go:503-508` and `resolveUpdateRef` (~1020-1047): accept `--allow-unsigned` in any position after `update`; `--from` stays
- Test: `internal/dbcmd/pull_test.go`, `internal/dbcmd/pullseed_test.go`, `cmd/assay/main_test.go`

**Interfaces:**
- Consumes: Task 2's `trust.Verify`, `trust.TrustedKeys`, `trust.ErrNotSigned`; Task 3's record fields.
- Produces: `func Pull(ctx context.Context, dbPath, ref string, allowUnsigned bool, stdout, stderr io.Writer) int`; `func resolveUpdateRef(args []string, stderr io.Writer) (ref string, allowUnsigned bool, ok bool)`. Messages: `error: <ref>@<digest> is not signed (no <sigtag> in the repository) — refusing to install; a mirror must copy the signature tag too, or pass --allow-unsigned to install it unverified`; `error: the signature on <ref>@<digest> does not verify under any key this assay trusts (<ids>)`; a transport failure keeps `error: fetch …`. With `allowUnsigned` and `ErrNotSigned`: stderr `WARNING: installing <ref>@<digest> UNVERIFIED (--allow-unsigned)`, record `Unverified: true`. `allowUnsigned` never excuses `ErrNoKeyVerifies` (a present, wrong signature is refused regardless).

- [ ] **Step 1: Write the failing caller tests** (reuse `publishedFrom`; add a helper `signPublished(t, ref, key)` in `pull_test.go` writing a `.sig` tag with Task 2's test helper shape — move `signTestPayload`/`writeSig` into an internal test-only package `internal/dbcmd/trust/trusttest` so both packages use them):
  - `TestPull_RefusesAnUnsignedArtifactBeforeUnpacking`: unsigned → exit 2, stderr contains `is not signed` and the sig tag name, `dbPath+".tmp"` does not exist, the live database untouched.
  - `TestPull_InstallsASignedArtifactAndRecordsTheKey`: signed by a key injected through a package-level `trustedKeys = trust.TrustedKeys` seam → exit 0, `Meta().Artifact.SignedBy == <id>`.
  - `TestPull_WrongKeyIsRefusedEvenWithAllowUnsigned`: signed by an untrusted key, `allowUnsigned=true` → exit 2, `does not verify`.
  - `TestPull_AllowUnsignedInstallsAndMarksTheRecord`: unsigned, `allowUnsigned=true` → exit 0, stderr `WARNING`, `Artifact.Unverified == true`, `db status` shows `signed:     NO`.
  - `TestPull_TransportFailureOnTheSigTagIsNotNotSigned`: 403 wrapper on the sig manifest → exit 2, stderr contains `403`, not `is not signed`.
  - `TestPullSeed_RefusesAnUnsignedSeed` and `TestPullSeed_AcceptsASignedSeed` (same shapes; no allow flag exists).
  - `cmd/assay`: `TestResolveUpdateRef_AllowUnsigned` (`["db","update","--allow-unsigned"]`, `["db","update","--from",ref,"--allow-unsigned"]`, `["db","update","--allow-unsigned","--from",ref]` all parse; `--from` alone → `allowUnsigned=false`).

- [ ] **Step 2: Run** `go test ./internal/dbcmd -run 'TestPull_|TestPullSeed_' -count=1; go test ./cmd/assay -run TestResolveUpdateRef -count=1` — FAIL.

- [ ] **Step 3: Implement**: in `Pull`, after the schema check and before `MkdirAll`/lock: `d, _ := img.Digest()`; `keyID, err := trust.Verify(ctx, target.Context(), d, trustedKeys(), remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))`; branch on `errors.Is(err, trust.ErrNotSigned) && allowUnsigned`; set `SignedBy`/`Unverified` in the `setArtifactFn` record. `PullSeed`: same, no flag. `main.go`: parse the flag; usage text gains one line.

- [ ] **Step 4: Run** the tests — PASS; `go test ./... -count=1` green (every existing `TestPull_*` fixture must now be signed: update `publishedFrom` to sign with a test key registered through the seam, so the old tests keep passing on signed artifacts).

- [ ] **Step 5: Commit** `feat(dbcmd): db update and db build --seed verify the artifact's signature before installing; --allow-unsigned is explicit and recorded (D137)`.

- [ ] **Step 6: Mutation round** (after the commit): `Verify` call deleted in `Pull` (red: unsigned test); deleted in `PullSeed`; `allowUnsigned` applied to `ErrNoKeyVerifies`; `Unverified` not set; `--from` implying the flag; verify moved after `Unpack` (red: the `.tmp` assertion).

### Task 10: D137 in the roadmap, DESIGN, CLAUDE.md (PR 2 docs)

**Files:**
- Modify: `docs/superpowers/specs/2026-07-29-assay-roadmap.md` + `.ko.md` (new `### D137` after D136: Decision / Why / Measured / Verified / Remaining uncertainty, citing the spike numbers and both mutation tables)
- Modify: `docs/DESIGN.md` + `.ko.md` (checkbox after the D136 line; the `db update` section gains `--allow-unsigned`; the bootstrap runbook from Task 6 is referenced)
- Modify: `CLAUDE.md` ("What this is": one sentence on D137)
- Modify: `docs/integrations.md` + `.ko.md` (mirrors: copy the `.sig` tag; `--allow-unsigned`)

- [ ] **Step 1: Write** the sections; KO in the same commit.
- [ ] **Step 2: Verify** the D-number is unused elsewhere (`grep -rn D137 docs CLAUDE.md`), CRLF/KELVIN check on edited files.
- [ ] **Step 3: Commit** `docs: D137 — the published artifact is signed and verified on pull (EN/KO)`.
- [ ] **Step 4:** PR 2 review workflow as for PR 1; merge; release v0.12.0 after merge (Task 5's release job then signs and pins the README).

---

## Self-review notes

- Spec coverage: keys/rotation (T1, T6 runbook), signing by digest + self-check (T4), `db-sign.yml` (T4), verification rules 1–4 (T2), call sites + `--from` + `--allow-unsigned` (T9), record/status/provenance (T3), release signing + provenance (T5), installer shape 1–6 (T7, T5 README rewrite), rollout order (T8 gate between PRs), tests + mutations (T2 S7, T9 S6), seeds-predating-signing runbook (T6).
- Review Focus items 1–3 are rows in T2, 4 is a row in T9, 5 is a case in T7.
- Open to the builder: whether `trusttest` is a package or a `_test.go` copy (prefer the package); the exact `sed` in T5's README step; the composite's input names.
