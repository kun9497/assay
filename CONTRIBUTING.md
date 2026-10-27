# Contributing to assay

Issues and pull requests are welcome. This page is what a change needs in order to be
merged; the reasoning behind each rule is in the documents it links to.

## Before you start

- **Check [docs/deferred-decisions.md](docs/deferred-decisions.md) before proposing a
  feature.** Most obvious gaps are either built already (each entry stays, marked resolved
  by the decision that closed it) or deferred on purpose, with the reasoning, what would
  change it, and the groundwork already in place. New information reopens an entry; the
  same argument again does not.
- **Read [docs/DESIGN.md](docs/DESIGN.md#architecture)** for the five interfaces a change
  must stay inside (`Source` → `Cataloger` → `Target` → `Matcher` → `Reporter`, with
  `Provider` filling the `Store` out of band), and the
  [roadmap](docs/superpowers/specs/2026-07-29-assay-roadmap.md) for the numbered decisions
  (`D1`…). Cite the decision a change touches.
- A security problem goes through [SECURITY.md](SECURITY.md), not an issue.
- A missed or extra finding is the most useful bug report: include the target (or a
  minimal SBOM reproducing it), the advisory ID, and what grype or the vendor says.

## Build and test

```bash
make build   # CGO_ENABLED=0, -trimpath -> bin/assay
make test    # go test -race ./...
make lint    # go vet ./...
make fmt     # gofmt -l -w .
```

`-race` needs a C toolchain; without one, run `go test ./...` and let CI run the race
detector. On Windows, run `make` under Git Bash or call the `go` commands directly. CI runs
gofmt-check, vet, `test -race` and build on Linux, and vet, test and build on Windows and
macOS; a non-empty `gofmt -l .` fails it.

## What a change needs

- **A test written first, and the caller's test before the helper's.** The defect this
  project repeats most is a well-tested helper that nothing calls: delete the call site and
  the suite stays green. Drive the code that calls the new function, assert an effect that
  differs when the call is gone, and only then test the helper's own branches.
- **Tests that can fail.** Before trusting a test, make the one-line change it should catch
  and watch it go red. Avoid `strings.Contains` on output where another field already holds
  the substring (`ALPINE-CVE-2025-46394` contains `CVE-2025-46394`).
- **Version comparison stays per ecosystem** (D9). A comparer change comes with a
  table-driven test reviewed line by line: an ordering mistake is a silent false negative.
- **Exit codes are a contract** (D11): `0` clean, `1` findings at or above the gate, `2`
  could not run or cannot be trusted, and `2` outranks `1`. Results go to stdout,
  diagnostics to stderr.
- **No new dependency without a reason.** There are five direct dependencies, each chosen on
  purpose; anything that needs cgo is out, because releases are built with
  `CGO_ENABLED=0`.
- **Documentation in both languages, in the same commit.** Every user-facing document ships
  as `X.md` (English, canonical) and `X.ko.md` (Korean). Keep identifiers, flags and paths in
  English on both sides. Implementation plans under `docs/superpowers/plans/` are English
  only and are deleted once merged.
- **A change to a decision** updates its `D` entry in the roadmap (both languages) and the
  checkbox in `docs/DESIGN.md`.

## Pull requests

Keep one concern per pull request, say which decision it implements or changes, and include
the commands you ran and their results. A change to what a scan reports on a real target
should show the target's numbers before and after; the weekly differential against grype
and trivy (`cmd/scandiff`) is the reference for what counts as a regression.

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
