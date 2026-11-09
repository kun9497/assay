# Operating envelope

*English · [한국어](operating-envelope.ko.md)*

This page is for a service that runs `assay scan` on targets it did not author — a customer's
image reference, a checkout it was handed, an SBOM uploaded through a form. It states what
the scanner bounds on its own, what the registry library it links bounds, what neither bounds
and the deployment therefore has to provide, and how to verify each clause. Every statement
here was checked against the code at the commit this page was written on and names the file
it rests on; the checklist's commands were derived from that code and have not been run — the
service's first S-2 report is their first run. A `D` number is the roadmap decision that chose the behaviour
(`docs/superpowers/specs/2026-07-29-assay-roadmap.md`). The deferred-decisions entry "Safe
handling of externally supplied targets" is the design-side record of the same boundary; this
page is its operational reading.

The short version: assay bounds **what it reads** (bytes per file, bytes per scan, link hops,
config size) and, when asked, **how long an image scan may take**. It does not bound **where
it connects**, **which credentials it finds**, **how much memory or CPU the process takes**, or
**what happens when it is killed**. Those four are the deployment's.

## 1. What assay bounds itself

Every bound below fails closed: the scan exits 2 (the CLI contract's "cannot be trusted",
D11) and prints no report, rather than continuing with a partial inventory. The numbers are
not configurable — a limit that moved per deployment would be a number nobody could reason
about in a bug report (D112, "What stays out") — and the two size limits are package-level
variables only so a test can lower them (`internal/source/limits.go`).

| Bound | Value | Where it applies | What exceeding it does | Decision |
|---|---|---|---|---|
| Per file | **512 MiB** decompressed (`MaxFileBytes`) | every file read out of an image layer (`Files`, `FilesUnder`, `FilesNamed`, `FilesMatching`); an SBOM target (`decodeSBOM` in `internal/scancmd/scancmd.go`); a jar archive's size on disk and each entry inflated from it (`internal/cataloger/jar/jar.go`) | exit 2: `<path> exceeds the 512 MiB per-file limit (D112)` | D112 |
| Per scan | **2 GiB** (`MaxScanBytes`) | the sum of every file read across every layer pass of one image; separately, the sum of everything one jar archive inflates, nested archives included | exit 2: `image reads exceeded the 2 GiB per-scan limit (D112) at <path>`; for a jar, `<archive> exceeds the 2 GiB per-archive decompression budget (D112) at <entry>` | D112 |
| Image config | **16 MiB** declared size (`MaxConfigBytes`) | the `config.size` a manifest declares, checked before the blob is requested | exit 2: `image config is declared at <n> bytes, past the 16 MiB per-config limit (D112)`; the blob is never fetched | D112 (QA 2026-11-02) |
| Link hops | **40** links per wanted path (`maxSymlinks`, `internal/source/walk.go`) — Linux's `MAXSYMLINKS`; a cycle ends at its first repeat | symlinks and hardlinks met while resolving `/etc/os-release` and the package databases inside an image | not exit 2 by itself: the path is reported `not read: <path> (still a link after 40 symbolic links ...)` on stderr, in the JSON `unread[]` and as SARIF `assay/not-read`, and trips `--fail-on-incomplete` (either scope). It becomes exit 2 when the lost path was the package database, because the scan then finds none | D109, D130, audit 2026-10-22 |
| Nested jars | **3** levels (`maxNestedDepth`, `internal/cataloger/jar/jar.go`) | archives inside a jar or war | an archive past the third level is a counted skip, never silent truncation | D70 |
| Directory depth | **6** levels below the root (`maxDepth`, `internal/cataloger/dirscan/walk.go`) | `dir:` targets | deeper directories are pruned, deliberately without disclosure — not an error | D26 |
| Time | **`--timeout <duration>`**, off by default | a registry fetch (`remote.WithContext`, `internal/source/image.go`) and the layer walks, which check the context before every tar entry and between 32 KiB chunks of the digest drain (`readLayer`, `drainLayer` in `internal/source/layerdigest.go`) | exit 2: `error: scan did not finish within <duration> (--timeout): <where the walk was>` | D112 |

Three things the table implies but a wrapper should read as plain statements:

**Without `--timeout` there is no deadline.** `cmd/assay/main.go` builds the scan's context
from `context.Background()` and adds a deadline only when the flag was given. The registry
library's default transport dials with a 30-second timeout and gives a TLS handshake 10
seconds, and nothing after that: a registry that accepts the connection and never answers, or
trickles a layer, holds the scan open indefinitely (the comment above `Open` in
`internal/source/image.go` says so in as many words). A service passes `--timeout` on every
image scan, and the value is recorded in the report's `provenance.policy` (D120).

**`--timeout` reaches image scans only.** An SBOM, directory, Go binary or jar target never
consults the context (D112, "What stays out"): the jar budget bounds that reader's work
directly, and a `dir:` target's lockfiles are read whole with `os.ReadFile` and no size limit
at all — a directory the operator points at is treated as theirs. A service that scans
customer checkouts bounds that path with the process limits of section 6, not with a flag.

**Layer passes multiply time, not memory.** Every lookup is a full pass over every layer,
newest first (`resolvePass` in `internal/source/walk.go`), and every pass reads each layer to
EOF so its diff id can be checked (D123). `Files` costs one pass plus one per link hop (at most
41); the distroless `status.d` pass runs only when `/var/lib/dpkg/status` is absent; the
pacman pass only when no apk, dpkg or rpm database was found; the two Bitnami passes
(`FilesMatching` on `/opt/bitnami`, then `Files` for the legacy path) run on every image
(`catalogFromImage` and `catalogBitnami` in `internal/scancmd/scancmd.go`). A minimal Alpine
image therefore costs four full passes, which is why `--timeout` exists: the size limits bound
what is kept, not how often a layer is decompressed.

## 2. What the registry library bounds

The registry path is `github.com/google/go-containerregistry` **v0.21.7** (`go.mod`), called
with only `remote.WithContext` and `remote.WithAuthFromKeychain` (`internal/source/image.go`),
so the library's defaults apply unchanged. These are facts about that version, read from the
module cache; a dependency bump can change any of them, and the reviewer of such a bump
should re-read this section.

| Library behaviour | Value | Source |
|---|---|---|
| Manifest and index body | **100 MiB** (`manifestLimit`) | `pkg/v1/remote/fetcher.go` |
| Bearer-token response body | **64 KiB** (`maxTokenBodySize`) | `pkg/v1/remote/transport/bearer.go` |
| Registry error body | **64 KiB** (`maxErrorBodySize`) | `pkg/v1/remote/transport/error.go` |
| Request retry | **3 attempts** in all (`Steps: 3`), waiting about 1 s after the first failure and 3 s after the second (`Duration: 1s`, `Factor: 3`, `Jitter: 0.1`); the loop runs the request once per step | `pkg/v1/remote/options.go` (`defaultRetryBackoff`), `internal/retry/wait` (`ExponentialBackoff`) |
| What is retried | temporary network errors, `io.EOF`, `io.ErrUnexpectedEOF`, `EPIPE`, `ECONNRESET`, `net.ErrClosed`; HTTP 408, 429, 500, 502, 503, 504, 499, 522. An expired context is never retried | `pkg/v1/remote/options.go` (`defaultRetryPredicate`, `defaultRetryStatusCodes`), `internal/retry/retry.go` |
| Redirect to a **private, loopback, link-local or unspecified IP literal** on another host | **refused**: `SSRF protection: redirect from "<host>" to private/link-local host "<ip>" denied` | `checkRedirectSSRF`, `pkg/v1/remote/fetcher.go` |
| Redirect to a **DNS name** (whatever it resolves to) | **followed** | same function: only `net.ParseIP` literals are checked |
| Redirect to the **same host** | **followed**, always | same function, compared against the first request's host (`via[0]`) |
| Foreign-layer URL (`urls[]` in a manifest) | must be `https` for a secure registry; a private or link-local IP-literal host is refused | `pkg/v1/remote/fetcher.go` |
| Proxy | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` honoured through `http.ProxyFromEnvironment` | `DefaultTransport`, `pkg/v1/remote/options.go` |
| Connection | dial 30 s, TLS handshake 10 s, no response-header or body timeout | `DefaultTransport`, `pkg/v1/remote/options.go` |

The redirect rule is narrower than it sounds, and the deferred-decisions entry spells it out:
the check compares each hop against the host the caller named, refuses only IP literals, and
never looks at the first request. A target whose own hostname resolves to `169.254.169.254`,
or a redirect to `metadata.internal.example` that resolves there, is fetched. That is the gap
section 6's egress policy closes.

Request-level retry is the library's; assay adds its own mid-stream retry only to `db update`
and `db build --seed` (D140), not to a scan's layer reads. A layer cut mid-download during a
scan is a failed scan (exit 2), which the wrapper may retry as a whole.

## 3. Memory model

What a scan holds in memory, and what nobody has measured yet.

**Buffered, bounded.** Every wanted file out of an image is read whole into memory under the
per-file limit (`readEntry`, `internal/source/limits.go`), and the files kept across a scan
are bounded by the per-scan limit — so an image scan holds at most 2 GiB of file content, plus
the manifest (≤ 100 MiB, library) and the config (≤ 16 MiB). The rest of each layer is
drained through a 32 KiB buffer and discarded (`drainLayer`); it costs time, not memory. An
SBOM is streamed through its decoder under the same 512 MiB read limit; the decoded structure
is the decoder's and is proportional to the document. A jar inflates at most 512 MiB per
entry and 2 GiB per archive. A Go binary is read through `debug/buildinfo.ReadFile`
(`internal/cataloger/gobinary/gobinary.go`), which reads sections, not the whole file.

**Buffered, unbounded.** A `dir:` target's lockfiles are read whole with `os.ReadFile`
(every cataloger under `internal/cataloger/*lock*`, `requirements`, `gomod`) with no size
check — by decision, see section 1. Memory for a hostile checkout is the cgroup's to bound.

**The database is memory-mapped.** A scan opens the store read-only
(`bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})`, `internal/store/bolt.go`), and
bbolt maps the whole file. Pages a lookup touches are paged in; the mapping is file-backed, so
it counts toward a cgroup's memory while being reclaimable. The size: the published artifact's
database layer was **482,350,701 bytes gzip-compressed** when its manifest was read for this
page (`ghcr.io/kun9497/assay-db:v9`, digest `sha256:ddd969bc…`, 2026-11-09). The uncompressed
size of the published database was not measured for this page; the only local figure is a
partial 2026-08 build at 3 GiB on disk on Windows, where bbolt extends the file to its mmap
size in 1 GiB steps (`bolt_windows.go`, `mmapSize` in `db.go`, bbolt v1.5.0), so that is an
upper bound of the data in it, not a measurement.

**Peak RSS has not been measured.** No number on this page is a measured resident-set size,
and none should be inferred from the bounds above: the bounds are ceilings on input, not on
the process. The measurement belongs on the weekly scanner-differential runner
(`.github/workflows/scanner-diff.yml`, `cmd/scandiff`), which already scans 26 pinned images
every week and is the one place a per-target peak can be recorded against a known input. Until
it exists, a deployment sets its memory limit from its own measurement on its own targets —
and reads a kill under that limit the way section 5 describes. The Go runtime's `GOMEMLIMIT`
is a soft target for the garbage collector, not a cap, and does not bound the mapped
database.

## 4. Credentials

A registry scan resolves credentials through one chain, first answer wins
(`internal/source/credentials.go`, D118):

1. **`ASSAY_REGISTRY_AUTH_USERNAME` + `ASSAY_REGISTRY_AUTH_PASSWORD`, or
   `ASSAY_REGISTRY_AUTH_TOKEN`**, scoped to the target's own registry unless
   `ASSAY_REGISTRY_AUTH_AUTHORITY` names another. A half-set credential is exit 2 before the
   registry is contacted (`newKeychain`, called in `internal/source/image.go`), never a
   silent fall-back to anonymous.
2. **The docker login** (`authn.DefaultKeychain`): consulted only when `~/.docker/config.json`
   or `$DOCKER_CONFIG/config.json` exists (`dockerConfigExists`). When the home file exists
   the library still loads from `$DOCKER_CONFIG`, so **a per-job `DOCKER_CONFIG` pointed at an
   empty directory does not fall back to `~/.docker`** — measured 2026-10-13 (D118) and the
   property the isolation row in section 7 tests. A `credHelpers`/`credsStore` entry runs the
   named `docker-credential-*` from `PATH`; reading the config is consent to run it.
3. **The podman login**: `$REGISTRY_AUTH_FILE`, else `$XDG_RUNTIME_DIR/containers/auth.json`,
   read by assay itself; an unset `XDG_RUNTIME_DIR` yields no path rather than a relative one
   (`podmanAuthPath`).

What the service can observe: when a credential was offered, one stderr line names the source
and nothing else — `registry credentials for <registry>: from the environment` (or `the
docker config`, `the podman auth file`; `catalogImage` in `internal/scancmd/scancmd.go`), and
the report's `provenance.target.registryCredentials` carries the same name (D120). A 401 or
403 is exit 2 naming the registry and the source that was offered. **No credential value
appears on stdout, stderr or in any report**; the library's JSON errors, which can quote a
byte of a hand-edited config, are reduced to an offset (`dockerConfigError`).

What the chain does not do: it does not isolate tenants. Every source is read from the
process's environment and the user's home, so two customers' scans on one host share whatever
login that host user holds unless each job gets its own `DOCKER_CONFIG`,
`REGISTRY_AUTH_FILE`/`XDG_RUNTIME_DIR` and `ASSAY_REGISTRY_AUTH_*` (D118, "What stays with
the deployment"). An SBOM, `docker-archive:` or `oci-dir:` scan never consults the chain.

## 5. Termination

**assay installs no signal handler.** There is no `os/signal` use anywhere under `cmd/` or
`internal/`, so `SIGTERM` and `SIGINT` take the Go runtime's default: the process exits at
once. Nothing deferred runs. In particular:

- **No exit-2 line is printed**, because the error path was never reached.
- **No `--provenance` sidecar is written.** The sidecar is written by `recorder.finish`,
  deferred from `Run` (`internal/scancmd/scancmd.go`) and called by `Refuse` for failures
  before `Run` (`internal/scancmd/provenance.go`) — "every exit path that follows argument
  parsing" (D120) means every path the program takes, and a kill is not one of them.
- **stdout may hold a partial report** if the kill lands during rendering.

A wrapper therefore treats **a missing sidecar as an untrustworthy result**, the same class as
exit 2 — it is the only honest reading, since the alternative is to count a scan that never
finished as clean. The sidecar is written with a single `os.WriteFile`, not a rename, so a
file that does not parse is read the same way. `--timeout` is the cooperative alternative: an
expired deadline is a normal exit 2 with its message, and the sidecar records `exitCode: 2`
and the error text. Set `--timeout` below the wrapper's own kill deadline so the scan ends
through the path that writes a record.

## 6. What the deployment must provide

These come from the deferred-decisions entry and from what sections 1–5 do not cover. None of
them is something assay could decide — each needs a notion of "this network", "this tenant" or
"this budget" that only the deployment has.

**Egress policy.** assay has no host allow-list and resolves whatever it is given; the only
refusals are the library's redirect-to-IP-literal and foreign-layer checks of section 2. Block
RFC 1918 ranges, link-local (`169.254.0.0/16`, the cloud metadata address included), loopback
and any internal DNS zone at the network layer of the scan sandbox. An SBOM, `docker-archive:`
or `oci-dir:` scan makes no network call at all, so a job that scans only those can run with
egress denied entirely.

**Per-tenant credentials.** One job, one `DOCKER_CONFIG` (an empty directory when the tenant
has none), one `REGISTRY_AUTH_FILE`, one set of `ASSAY_REGISTRY_AUTH_*`; a `PATH` that holds
no credential helper the tenant did not ask for. Verify with the stderr source line (section 4).

**Process limits.** CPU, memory and pids through the cgroup (`docker run --memory --cpus
--pids-limit`, `systemd-run -p MemoryMax= -p CPUQuota= -p TasksMax=`, or the orchestrator's
equivalent). assay bounds its input, not its process; the memory limit has to come from a
measurement on the deployment's own targets (section 3), and a scan the limit kills is read as
section 5 says.

**A concurrency cap.** Nothing in assay limits how many scans run at once, and each one holds
up to the section 3 buffers. One database file serves any number of concurrent read-only
scans; only `db update` and `db build` take the writer lock (D116), and a scan never waits on
it.

**Disk.** The scan path writes nothing but what it is told to — the report to stdout and the
`--provenance` sidecar; there is no `os.CreateTemp` or `os.MkdirTemp` under
`internal/source`, `internal/scancmd` or `internal/cataloger` (the temp files are the
providers' and `db push`'s). The database lives at `$ASSAY_DB_DIR`, else the user cache
directory (`store.DefaultPath`, `internal/store/store.go`); `db update` builds `<dbPath>.tmp`
beside it and renames over it under `<dbPath>.lock` (D116), so the database volume needs room
for two copies during an update. Pull once per host or per job, then scan read-only.

**The working directory.** With no `--config`, a scan discovers `.assay.yaml` in the directory
it runs from and applies its waivers, so a checkout the service did not author can waive its
own findings. Pass `--config none` (recorded as `ignoreFile.path: "none"` in the provenance).

**Target-kind validation before exec.** The deployment decides which target kinds a tenant may
submit; assay has no flag for it. `source.Classify` (`internal/source/classify.go`) returns
the kind it will scan as — `TargetImage`, `TargetSBOM`, `TargetDirectory`, `TargetGoBinary`,
`TargetJar` — with a bare local path decided by content and `os.Stat`, and an image further
split into a registry reference, `oci-dir:` or `docker-archive:` (`classify` in
`internal/source/image.go`). A wrapper that accepts registry references only must refuse bare
paths and the two local image schemes itself, before `exec`.

**An explicit `--platform`.** The default is the scanning host's platform (D119). A service
scanning for a tenant passes the platform the tenant runs, so the scanned image is the one that
would be deployed; the report's `image.match` says whether it was exact, compatible or a
mismatch.

## 7. Checklist for the S-2 test report

One row per clause of the pass condition. Each command is the smallest observation that
distinguishes the fact from its absence; run them from inside the scan sandbox, with the
process limits of section 6 in place. The commands and expected observations were derived
from the code the last column names and have not been executed by this page's authors —
exit statuses such as `timeout`'s 124 are the tools' documented values, not observed ones.

| Clause | Command | Expected observation | The fact it rests on |
|---|---|---|---|
| Registry DNS and redirects | Stand up a test registry that answers a blob request with `302` to `http://169.254.169.254/latest/` once, and to `http://<name that resolves to 10.0.0.5>/` once; `assay scan <registry>/img:tag --timeout 2m` against each | First: exit 2, stderr contains `SSRF protection: redirect from "<registry>" to private/link-local host "169.254.169.254" denied`. Second: the redirect is **followed** — the scan fails only if the network blocks it | `checkRedirectSSRF` (go-containerregistry v0.21.7): IP literals refused, DNS names followed |
| Private networks | `assay scan <name resolving to 10.x or 169.254.x>/img:tag --timeout 1m` with the sandbox's egress policy on, then off | On: exit 2 with a connection error naming the target; no bytes fetched. Off: assay connects and fetches — the policy, not the scanner, is what stopped it | deferred-decisions, "Safe handling of externally supplied targets": no allow-list in assay |
| Credential isolation | `docker login <registry>` as the host user; then `DOCKER_CONFIG=$(mktemp -d) REGISTRY_AUTH_FILE=/nonexistent assay scan <registry>/private:tag 2>err.txt`; then the same with `ASSAY_REGISTRY_AUTH_USERNAME/PASSWORD` set; `grep -c "$PASSWORD" err.txt` | First run: exit 2, `UNAUTHORIZED`, no `registry credentials for` line (the home login was not used). Second: exit 0/1, stderr `registry credentials for <registry>: from the environment`. Both: the grep prints `0` | D118; `dockerConfigExists`, `podmanAuthPath` in `internal/source/credentials.go` |
| CPU/memory/disk/concurrency limits | `N` concurrent `assay scan <image> --timeout 10m --provenance p$i.json` under `docker run --memory=<M> --cpus=<C> --pids-limit=<P>`; `strace -f -e trace=openat` or a before/after listing of `$TMPDIR` and `$ASSAY_DB_DIR` | Every run ends with a sidecar whose `exitCode` is 0, 1 or 2 — a missing sidecar means the limit killed it and `M` is below that target's peak; no file created outside stdout, the sidecars and the database directory | section 3 (buffers bounded, RSS unmeasured); no `CreateTemp`/`MkdirTemp` on the scan path; read-only `bolt.Open` |
| Forced termination | `timeout -s TERM 5 assay scan <large image> --provenance p.json; echo $?; test -f p.json` | Shell status 124 (or 143 when run bare); **no** `error:` line on stderr; `p.json` absent | no `os/signal` use in `cmd/` or `internal/`; `recorder.finish` runs only on a returned exit |
| Long-running operation | `assay scan <registry that accepts TCP and never answers>/img:tag --timeout 10s --provenance p.json; echo $?`; then once more without `--timeout`, with a wall clock | With the flag: exit 2 within ~10 s, stderr `error: scan did not finish within 10s (--timeout): …`, `p.json` present with `"exitCode": 2`. Without: the scan is still running after the 30 s dial and 10 s TLS budgets have passed, until the wrapper kills it | D112; `context.Background()` plus `withScanTimeout` in `cmd/assay/main.go`; the `Open` comment in `internal/source/image.go` |

A row whose observation differs from the table is a finding against this page or against the
code, and either way belongs in an issue with the `assay version` line — the facts here are
tied to the commit they were read at.
