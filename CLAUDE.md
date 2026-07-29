# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`assay` is a vulnerability scanner (Go, module `github.com/kun9497/assay`) that covers the
whole path in one tool: build the package inventory from an image/binary/directory, build
the vulnerability database, and match the two. In the anchore ecosystem those are three
separate projects (`syft`, `vunnel` + `grype-db`, `grype`).

It is currently a **scaffold**: `cmd/assay/main.go` is the only source file and `scan` is
unimplemented. The README's Architecture section is the agreed design target, not shipped
code — do not assume those packages exist.

Design work in progress lives in `docs/superpowers/specs/`. Read the roadmap there before
proposing structural changes.

## Commands

```bash
make build        # CGO_ENABLED=0, -trimpath, version/commit/date via -ldflags -> bin/assay
make test         # go test -race ./...
make lint         # go vet ./...
make fmt          # gofmt -l -w .
```

Run a single test: `go test -race -run TestRun_ExitCodes ./cmd/assay`

The Makefile shells out to `date` and `rm`, so on Windows either run it under Git Bash or
call the underlying `go` commands directly. CI (`.github/workflows/ci.yml`) runs
gofmt-check → vet → test -race → build on Go 1.24; a non-empty `gofmt -l .` fails the build.

`CGO_ENABLED=0` in the Makefile is a real constraint on dependency choice — anything
requiring cgo (notably `mattn/go-sqlite3`) is unavailable. Pure-Go alternatives only.

## Architecture constraints

Five interfaces carry the design; keep changes inside these boundaries.
`Source` → `Cataloger` → `Target{Distro, []Package}` → `Matcher` (using `Store` +
`Comparer`) → `Reporter`. `Provider` populates the `Store` out of band.

**The database is orthogonal to the scan.** `Provider`s write it via `assay db update`;
a scan only reads. Offline operation is the default, not a flag — do not introduce network
calls on the scan path.

**Advisories are stored in OSV shape** (`affected[].ranges[]` with `introduced`/`fixed`
events). Every provider normalizes into that form rather than the store growing per-source
variants.

**Ecosystem keys include the distro release** — `Alpine:v3.19`, not `Alpine` — because the
fixed version differs per release. The distro itself lives on `Target`, not `Package`: an
image is Alpine 3.19, its packages are not.

**Version comparison stays per-ecosystem.** Debian epochs, RPM release ordering, semver
pre-release precedence, and Maven ordering genuinely disagree. Never collapse `Comparer`
implementations into a shared `compareVersions` — the README calls this out as the specific
bug the design avoids.

**`Finding` carries `Evidence`.** Explainability is goal #1; if the evidence is not in the
type it will end up in log lines and effectively not exist.

## CLI contract

Exit codes are contract, not implementation detail (`exitOK`/`exitFindings`/`exitError` in
`main.go`): `0` = clean, `1` = findings at or above `--fail-on`, `2` = the scan could not
run. CI must never confuse "found nothing" with "was broken". This is why the unimplemented
`scan` returns `exitError` and a test asserts it — preserve that property in any partial
implementation.

**Stream discipline**: results to stdout, diagnostics to stderr, so
`assay scan ... --output json | jq` stays clean. `main_test.go` enforces both directions.

**`run(args, stdout, stderr) int` is the testable seam** — `main()` only translates its
return into `os.Exit`. New commands go in the `run` switch and take writers, never touching
`os.Stdout` or `os.Exit` directly.

## Conventions

- No third-party dependencies yet (`go.mod` has no `require` block). Adding one is a real
  decision — prefer the stdlib, and check the cgo constraint above.
- Comments explain *why* a choice was made (see the exit-code and TODO comments in
  `main.go`); match that register rather than narrating what the code does.
