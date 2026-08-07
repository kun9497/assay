// Command assay is an SBOM-driven vulnerability scanner.
//
// See https://github.com/kun9497/assay for design notes and roadmap.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/dbcmd"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/provider/knvd"
	"github.com/kun9497/assay/internal/provider/nvd"
	"github.com/kun9497/assay/internal/provider/osv"
	"github.com/kun9497/assay/internal/provider/redhat"
	"github.com/kun9497/assay/internal/scancmd"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/store"
)

// Build-time metadata, injected via -ldflags. See the Makefile.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Exit codes. These are part of the CLI contract: CI systems must be able to
// distinguish "the scan ran and found something" from "the scan could not run".
const (
	exitOK       = 0 // completed, nothing at or above the fail-on threshold
	exitFindings = 1 // completed, findings at or above the threshold
	exitError    = 2 // could not complete
)

const usage = `assay — SBOM-driven vulnerability scanner

Usage:
  assay <command> [arguments]

Commands:
  scan <target>   Scan a CycloneDX SBOM, an image reference, a docker-archive:
                  tarball, an oci-dir: layout, a Go binary, or a directory
                  containing a go.mod (Go, npm, PyPI, Alpine). What a bare
                  path names is decided by its content; prefix it with
                  sbom:, file:, or dir: to say which it is when that would
                  be ambiguous. A directory is read from its go.mod alone -
                  what the module requires, not what a build would link.
  db update       Download the published vulnerability database
  db build        Build the vulnerability database from its upstream sources
  db status       Show what is in the database and how current it is
  db push <ref>   Publish the built database as an OCI artifact (builders only).
                  Refuses to narrow the published coverage; --force overrides.
  db ref          Print the registry tag this binary's schema reads (CI only)
  version         Print version information
  help            Show this help

Scan flags (any order, before or after the target):
  --fail-on <band>      Exit 1 if a finding is at or above <band>
                        (none, low, medium, high, critical)
  --fail-on-unknown     Exit 1 if a finding's severity could not be rated
  --fail-on-unfixable   Exit 1 if a finding has no fix available from any
                        source - the vendor says the package is affected and
                        will not be fixed, or nobody recorded a version to
                        move to. Reported and counted either way; this makes
                        it fail the build.
  --fail-on-incomplete[=any|target]
                        Exit 2 if any package's evaluation was incomplete.
                        =target narrows it to causes you can act on (a version
                        in the scanned artifact that will not parse), leaving
                        out malformed advisory data you cannot fix.
  --output <format>     table (default) or json
  --explain <id>        Print one advisory's full Evidence (its own ID, or
                        any alias/upstream identifier) instead of the report

db update flags:
  --from <ref>    Pull from a different registry reference (a mirror, or a
                  pinned digest). The default derives its tag from the
                  schema version this binary reads.

db build flags:
  --seed <ref>    Layer onto a previously published database (D-seed): its
                  RATINGS are carried forward, its advisories are not --
                  every advisory is rebuilt from the providers below
                  regardless, so one upstream withdraws stays gone. This is
                  what lets a scheduled build fit a six-hour job cap instead
                  of repeating the seven-hour full pass. A seed that cannot
                  be read fails the build rather than silently building from
                  empty.

Environment (db build only — a scan reads no environment and no network):
  NVD_ENABLE=1          Also fetch NIST's CVSS scores, so findings whose
                        advisory carries no severity can still be rated.
                        Off by default: a full pass takes about seven hours.
  NVD_SINCE_DAYS=<n>    Bound that fetch to CVEs modified in the last n days
                        (max 120). Bounds ONE BUILD, not a delta on the last
                        one — db status prints the window it covered.
  NVD_API_KEY=<key>     Raise NVD's rate limit tenfold. Optional, and it does
                        not shorten the seven hours; NVD's own response
                        generation is the bottleneck, not the pacing.
  REDHAT_ENABLE=1       Also fetch Red Hat's CSAF VEX feed, which is the only
                        source that can say a RHEL package is affected and
                        WILL NOT BE FIXED. OSV's Red Hat export is errata-only
                        and cannot express that at all, so without this a scan
                        reports 21,938 such CVEs as clean (D43, D48).
                        Off by default for size, not for licensing: the feed is
                        TLP:WHITE and freely redistributable, but the archive is
                        262 MB compressed / 17.1 GB streamed and contributes
                        about 1.9 million affected entries, two thirds of which
                        no upgrade can resolve.
  KISA_ENABLE=0         Skip KISA/KNVD's Korean security notices. ON BY
                        DEFAULT (D37): attaching them is what this project was
                        built for, and leaving it to a flag meant the flagship
                        feature was off for everyone who forgot. The fetch is
                        about 41 requests and under a minute, and a failure
                        warns rather than failing the build - enrichment
                        cannot change a verdict.
                        This data is LOCAL ONLY: KISA's terms do not permit
                        redistributing it, so db push strips it and db update
                        never delivers it. Set this to 0 when the result is
                        going to be pushed anyway, which is why the publish
                        workflow does.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run holds the real entry point so it stays testable — main only translates
// the result into a process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}

	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "assay %s (commit %s, built %s)\n", version, commit, date)
		return exitOK

	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return exitOK

	case "scan":
		// args[1:] on a length-1 slice (just "scan") is a valid empty slice,
		// not a panic, and parseScanArgs of an empty slice returns target ==
		// "" with a nil error — so the target == "" check below already
		// covers "no target" without a separate len(args) < 2 guard ahead of
		// it. Two sites emitting the identical message was one more place for
		// them to drift apart, for no behavioural difference.
		target, opts, err := parseScanArgs(args[1:])
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitError
		}
		if target == "" {
			fmt.Fprintln(stderr, "error: scan requires a target")
			fmt.Fprint(stderr, usage)
			return exitError
		}
		return scan(context.Background(), target, opts, stdout, stderr)

	case "db":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "error: db requires a subcommand (update, build, status, push, ref)")
			return exitError
		}
		path, err := store.DefaultPath()
		if err != nil {
			fmt.Fprintf(stderr, "error: locate database: %v\n", err)
			return exitError
		}
		switch args[1] {
		case "build":
			ref, hasSeed, ok := resolveBuildSeed(args, stderr)
			if !ok {
				return exitError
			}
			seedPath := ""
			if hasSeed {
				// A scratch directory, not dbPath's own directory: the seed
				// is read-only input to this build, kept apart from the tmp
				// file Update itself builds into so the two can never
				// collide or be cleaned up by each other's logic.
				dir, err := os.MkdirTemp("", "assay-seed-")
				if err != nil {
					fmt.Fprintf(stderr, "error: create seed scratch directory: %v\n", err)
					return exitError
				}
				defer os.RemoveAll(dir)
				seedPath = filepath.Join(dir, "seed.db")
				// Pull's own exit code and stderr already explain what went
				// wrong. Returning it as-is (never falling through to build
				// from empty) is Task 5's whole point: the scheduled builder
				// passes --seed every night, so a registry outage must fail
				// loudly rather than quietly publish a one-day database over
				// a complete one.
				if code := dbcmd.Pull(context.Background(), seedPath, ref, stdout, stderr); code != 0 {
					return code
				}
			}
			// ref is what the disclosure names the seed as -- the original
			// reference, not seedPath's scratch file above, which an
			// archived CI log would not recognize.
			return dbcmd.Update(context.Background(), path, seedPath, ref,
				dbUpdateProviders(stderr),
				dbUpdateAnnotators(stderr),
				dbUpdateEnrichers(stderr),
				stdout, stderr)
		case "update":
			ref, ok := resolveUpdateRef(args, stderr)
			if !ok {
				return exitError
			}
			return dbcmd.Pull(context.Background(), path, ref, stdout, stderr)
		case "status":
			return dbcmd.Status(path, stdout, stderr)
		case "push":
			ref, force, ok := resolvePushRef(args, stderr)
			if !ok {
				return exitError
			}
			return dbcmd.Push(context.Background(), path, ref, force, stdout, stderr)
		case "ref":
			// Prints to stdout: it is a result a CI workflow captures to tag
			// what `db push` publishes, not a diagnostic. Reading it from the
			// binary rather than duplicating the tag as a literal in the
			// workflow keeps the two from drifting apart on a schema bump.
			fmt.Fprintln(stdout, dbcmd.Ref(dbcmd.DefaultRef))
			return exitOK
		default:
			fmt.Fprintf(stderr, "error: unknown db subcommand %q\n", args[1])
			return exitError
		}

	default:
		fmt.Fprintf(stderr, "error: unknown command %q\n", args[0])
		fmt.Fprint(stderr, usage)
		return exitError
	}
}

// nvdOptionsFromEnv reads NVD_API_KEY and builds the nvd.Options the
// annotator is constructed from. Pulled out as its own function, separate
// from constructing the annotator itself, so a test can assert the key was
// read and forwarded (D27's own contract: "the provider must never read the
// environment itself, that is why it takes an option") without db update
// making a real network call — nvd.New defaults BaseURL to the live NVD
// endpoint, so exercising construction end to end here would either hit the
// network or need a second seam just for tests.
//
// The key is optional and never required: NVD_API_KEY absent yields
// Options{APIKey: ""}, which nvd.New already treats as "send no apiKey
// header" (a slower, unauthenticated sync, not a failure).
// NVD_SINCE_DAYS additionally bounds the sync to CVEs modified in the last N
// days, using NVD's own lastModStartDate filter. Absent means the whole feed.
//
// Measured 2026-08-03, and the reason this exists: a full pass is about seven
// hours, because NVD generates each 2,000-record page in 114-136 seconds
// whatever the page size or compression. The rate-limit pauses are 20 minutes
// of that. Above 120 days the API rejects the window outright, so the value is
// capped here rather than sent and refused.
//
// It bounds ONE BUILD; it is not a daily delta, and this comment used to say
// it was. `db update` builds into a fresh database and renames over the live
// one, so nothing carries an earlier pass forward: a bounded run's window is
// the database's entire NVD coverage. Following the "full pass once, then
// NVD_SINCE_DAYS=1 nightly" recipe this comment previously recommended would
// leave ~300 ratings where there had been ~372,000, and every finding whose
// CVE was not touched yesterday would quietly fall back to unknown. Real
// deltas need the builder to layer onto an existing database, which is slice
// 8's job. Until then the window is disclosed instead (Provenance.Window).
//
// It is an environment variable rather than a flag because it is a property
// of how a database is being built, not of one scan. A flag can come later.
func nvdOptionsFromEnv(stderr io.Writer) nvd.Options {
	// Progress goes to stderr so retry notices are visible. Leaving it unset
	// defaults it to io.Discard, and that is exactly what shipped: a run that
	// spent 5h52m, hit a 503, retried four times and gave up printed nothing
	// about any of it, so the log read "retries fired: 0" when four had. The
	// option existed and was never connected — the observability was written
	// and then thrown away one call site later.
	opts := nvd.Options{APIKey: os.Getenv("NVD_API_KEY"), Progress: stderr}
	raw := os.Getenv("NVD_SINCE_DAYS")
	if raw == "" {
		return opts
	}
	// Every rejected value below silently produced a seven-hour full sync
	// before this warned, which is the opposite of what someone setting a
	// window wants and gives no clue why.
	days, err := strconv.Atoi(raw)
	switch {
	case err != nil || days <= 0:
		fmt.Fprintf(stderr, "warning: NVD_SINCE_DAYS=%q is not a positive number of days; syncing the whole feed\n", raw)
		return opts
	case days > 120:
		fmt.Fprintf(stderr, "warning: NVD_SINCE_DAYS=%d exceeds the API's 120-day maximum window; using 120\n", days)
		days = 120
	}
	opts.Since = time.Now().UTC().AddDate(0, 0, -days)
	return opts
}

// newNVDAnnotator constructs the NVD annotator. A package variable, not a
// direct call to nvd.New at the "update" call site, so a test can substitute
// a spy and observe what Options actually reached it — proving NVD_API_KEY
// is threaded all the way through to construction, not just read
// (nvdOptionsFromEnv's own test only proves the read half; a mutation
// dropping the argument entirely, e.g. `nvd.New(nvd.Options{})`, still
// compiled and left that test, and every other test in this package, green).
// Swapping this out never needs a network call: the spy can return the same
// real *nvd.Provider nvd.New would have, or nothing at all, since dbUpdateAnnotators
// itself never calls Annotate.
var newNVDAnnotator = nvd.New

// nl is a newline, assembled rather than typed. CLAUDE.md records the hazard
// and it fired twice while this file was being edited: a literal escape inside
// a script that writes Go collapses into the byte it denotes, and the file
// stops compiling. rune(10) cannot collapse.
var nl = string(rune(10))

// envFlag reads a boolean environment variable, falling back to def when it is
// unset or empty.
//
// It exists because the shape it replaces — `os.Getenv(name) != ""` — reads
// KISA_ENABLE=0 as ON. That was harmless while both flags were opt-in and
// nobody had a reason to write a falsy value, and it stopped being harmless the
// moment D37 made one of them default-on and the publish workflow needed to
// turn it off. An "off" switch that silently means "on" is worse than none: the
// caller believes the fetch is disabled and it runs anyway.
//
// An unrecognised value is a warning and the default, not an error. This is a
// database build, not a scan; refusing to start over a malformed environment
// variable would trade a fetch nobody wanted for a build nobody got, and the
// warning is on stderr where the rest of the build's diagnostics are.
func envFlag(stderr io.Writer, name string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		fmt.Fprintf(stderr, "warning: %s=%q is not a boolean; using the default (%v)"+nl,
			name, os.Getenv(name), def)
		return def
	}
}

// dbUpdateAnnotators is every provider.Annotator `db update` runs, built
// from the environment. Pulled out of the "update" case as its own function
// so a test can call it directly and inspect what reaches newNVDAnnotator.
//
// NVD is opt-in, via NVD_ENABLE. It ran unconditionally at first, which was
// wrong twice over:
//
//   - It made a NIST outage fatal to building ANY database. A configured
//     annotator failing must fail the build (dbcmd.Update explains why: a
//     database missing ratings it was supposed to have looks complete and
//     under-reports). But 503s from services.nvd.nist.gov are routine, and
//     with no way to unconfigure NVD that rule left a user unable to build
//     even the OSV-only database that worked yesterday.
//   - It moved the default cost of `db update` from minutes to seven hours,
//     with no way back.
//
// A full NVD pass is a builder's job, not every user's — which is exactly
// what slice 8 exists to fix. Opt-in is the honest state until then.
func dbUpdateAnnotators(stderr io.Writer) []provider.Annotator {
	// Still opt-in: the full pass costs hours, so a build that starts one
	// nobody asked for is a different kind of surprise from a fetch that takes
	// a minute (D37).
	if !envFlag(stderr, "NVD_ENABLE", false) {
		return nil
	}
	return []provider.Annotator{newNVDAnnotator(nvdOptionsFromEnv(stderr))}
}

// newRedHatProvider constructs the Red Hat CSAF VEX provider. A package
// variable for the same reason newNVDAnnotator and newKNVDEnricher are: a test
// can substitute a spy and observe the Options that reached construction,
// without redhat.New's default BaseURL — the live 262 MB archive — ever being
// fetched from.
var newRedHatProvider = redhat.New

// dbUpdateProviders is every provider.Provider `db build` runs.
//
// OSV is unconditional. Red Hat is opt-in via REDHAT_ENABLE, and the reasoning
// is a third one, different from both NVD's and KISA's:
//
//   - Not redistribution. The feed is TLP:WHITE on all 67,261 documents, so
//     unlike KISA (D29) whatever is built from it can be published.
//   - Not runtime either, quite. The archive is 262 MB compressed and 17.1 GB
//     decompressed and takes about ninety seconds to stream, which is
//     noticeable but nothing like NVD's seven hours.
//
// What makes it opt-in is SIZE OF RESULT. It contributes roughly 1.9 million
// affected entries against the OSV corpus's whole database, and two thirds of
// them are records that can never be resolved by upgrading — a RHEL host is
// simply affected. Turning that on for everyone by default would change what
// `assay db update` produces for people who never scan a RHEL image, and D37's
// argument for defaulting KISA ON was precisely that it costs almost nothing
// and changes nothing for anyone not looking at it. This is the opposite case.
func dbUpdateProviders(stderr io.Writer) []provider.Provider {
	ps := []provider.Provider{osv.New(osv.Ecosystems, "")}
	if envFlag(stderr, "REDHAT_ENABLE", false) {
		// Progress goes to stderr for nvd's reason: this provider discards the
		// large majority of what it reads, and a run that printed nothing
		// about it would be indistinguishable from one that was broken.
		ps = append(ps, newRedHatProvider(redhat.Options{Progress: stderr}))
	}
	return ps
}

// newKNVDEnricher constructs the KISA/KNVD enricher. A package variable for
// the same reason newNVDAnnotator is one: a test can substitute a spy and
// observe the Options that actually reached construction, without knvd.New's
// default BaseURL (the live KNVD endpoint) ever being fetched from.
var newKNVDEnricher = knvd.New

// dbUpdateEnrichers is every provider.Enricher `db build` runs, built from
// the environment.
//
// KISA is opt-in via KISA_ENABLE, exactly as NVD is via NVD_ENABLE, though
// the reasoning is different in kind: the NVD pass costs seven hours, while
// this one is ~41 requests and under a minute. What makes it opt-in is D29 —
// the data may not be redistributed, so `db push` strips it and `db update`
// never carries it, which means the only person who can get it is someone who
// deliberately built it themselves. An off-by-default flag is the honest
// shape for something a user has to opt into holding.
//
// A failing enricher does not fail the build (see dbcmd.Update), so enabling
// this cannot cost anyone their database the way an unconditional NVD did.
func dbUpdateEnrichers(stderr io.Writer) []provider.Enricher {
	if !envFlag(stderr, "KISA_ENABLE", true) {
		return nil
	}
	// Progress goes to stderr so the per-page and retry lines are visible.
	// Leaving it unset defaults it to io.Discard, and that is exactly what
	// shipped in nvd: a run that spent 5h52m, hit a 503 and retried four times
	// printed nothing about any of it, so the log read "retries fired: 0". The
	// option existed and was thrown away one call site later; this is that
	// call site.
	return []provider.Enricher{newKNVDEnricher(knvd.Options{Progress: stderr})}
}

// resolveUpdateRef decides which reference `db update` pulls from: the
// default, schema-derived ref (dbcmd.Ref(dbcmd.DefaultRef)), or an explicit
// override via `--from <ref>`. Pulled out of the "update" case as its own,
// network-free function — matching parseScanArgs' own separation from the
// commands that act on what it parses — so a test can drive every
// argument shape directly rather than only through run()'s full dispatch to
// dbcmd.Pull. That distinction matters here specifically: reaching Pull with
// the unvalidated default ref would mean an actual attempt to fetch from
// the real ghcr.io, which is exactly the network access no test may make,
// so a bug in the validation below could otherwise only be proven by a test
// that risks doing the very thing D14 forbids.
//
// A missing value ("--from" with nothing after it) or an unrecognized third
// argument (a typo'd "--form", or anything else) is an error, not a silent
// fall-through to the public default: someone pointing --from at a mirror
// or a pinned digest, or relying on it specifically because they are
// air-gapped, must not be quietly redirected to ghcr.io by a missing value
// or a typo.
func resolveUpdateRef(args []string, stderr io.Writer) (ref string, ok bool) {
	if len(args) <= 2 {
		return dbcmd.Ref(dbcmd.DefaultRef), true
	}
	if args[2] != "--from" {
		fmt.Fprintf(stderr, "error: unknown db update flag %q (want --from <ref>)\n", args[2])
		return "", false
	}
	if len(args) < 4 {
		// Derived, never spelled out. A literal tag here is a hardcoded schema
		// version that drifts the moment SchemaVersion is bumped, and this one
		// had: it still read :v6 after the bump to v7, telling a user to fetch
		// a tag that 404s. dbcmd.Ref is the same function `db ref` prints and
		// the default this very function returns two branches up.
		fmt.Fprintf(stderr, "error: --from requires a reference, e.g. %s\n", dbcmd.Ref(dbcmd.DefaultRef))
		return "", false
	}
	return args[3], true
}

// resolveBuildSeed decides whether `db build` should layer onto a published
// database: absent by default (has == false, today's from-empty build), or
// an explicit `--seed <ref>`. Split out and network-free for the same
// reason resolveUpdateRef is: a test can drive every argument shape
// directly, without reaching dbcmd.Pull with an unvalidated ref (an actual
// network call, which no test here may make).
//
// A missing value or an unrecognized flag is rejected outright rather than
// silently building from empty — the scheduled builder passes --seed every
// night specifically to avoid the seven-hour full pass, so a typo silently
// falling back to it would turn into a job that blows the six-hour cap
// instead of failing fast and loud.
func resolveBuildSeed(args []string, stderr io.Writer) (ref string, has, ok bool) {
	if len(args) <= 2 {
		return "", false, true
	}
	if args[2] != "--seed" {
		fmt.Fprintf(stderr, "error: unknown db build flag %q (want --seed <ref>)\n", args[2])
		return "", false, false
	}
	if len(args) < 4 {
		fmt.Fprintf(stderr, "error: --seed requires a reference, e.g. %s\n", dbcmd.Ref(dbcmd.DefaultRef))
		return "", false, false
	}
	return args[3], true, true
}

// resolvePushRef validates `db push`'s arguments: exactly one reference, no
// more. Split out and network-free for the same reason resolveUpdateRef and
// resolveBuildSeed are: a test can drive every argument shape without
// dbcmd.Push ever running.
//
// The trailing-argument rejection makes push consistent with update
// (resolveUpdateRef): `db update` already refuses an unrecognized third
// argument rather than silently ignoring it, and `db push ref junk` passing
// silently — publishing to `ref` while `junk` is dropped on the floor — was
// the exact "flag or argument accepted, then ignored" shape update's own
// rejection exists to prevent, D18's divergence-table concern applied to
// positional arguments instead of a flag.
func resolvePushRef(args []string, stderr io.Writer) (ref string, force bool, ok bool) {
	rest := args[2:]
	// --force is accepted on either side of the reference. It overrides the
	// coverage guard, so it is spelled out rather than abbreviated: the
	// thing it permits is replacing everyone's database with a narrower one.
	var positional []string
	for _, a := range rest {
		if a == "--force" {
			force = true
			continue
		}
		positional = append(positional, a)
	}
	switch len(positional) {
	case 0:
		// The audience here is a PUBLISHER, so a stale tag is worse than it is
		// two branches up: following it publishes a v7 database under the v6
		// tag, where every v6 client would pull a schema it refuses and every
		// v7 client would still 404.
		fmt.Fprintf(stderr, "error: db push needs a reference, e.g. %s\n", dbcmd.Ref(dbcmd.DefaultRef))
		return "", false, false
	case 1:
		return positional[0], force, true
	default:
		fmt.Fprintf(stderr, "error: unexpected argument %q: db push takes exactly one reference (already have %q)\n",
			positional[1], positional[0])
		return "", false, false
	}
}

// scan is the pipeline entry point: parse the target into an inventory, match
// it against the local database, and report.
func scan(ctx context.Context, target string, opts scancmd.Options, stdout, stderr io.Writer) int {
	path, err := store.DefaultPath()
	if err != nil {
		fmt.Fprintf(stderr, "error: locate database: %v\n", err)
		return exitError
	}
	return scancmd.Run(ctx, path, target, opts, stdout, stderr)
}

// parseScanArgs splits a scan command's arguments into the target and the
// --fail-on* gates, in any order relative to each other.
//
// The stdlib flag package will not do here: it stops parsing at the first
// non-flag argument, and the target — a bare positional argument such as
// alpine:3.19 — IS that first non-flag argument whenever it comes before the
// flags, which is how every example in the roadmap and the plan writes it
// (`assay scan alpine:3.19 --fail-on high`). A flag package that stopped
// there would silently hand "--fail-on" and "high" back as unparsed
// arguments instead of an error, which is exactly the "typo becomes no gate"
// failure the brief calls out.
//
// An empty target with a nil error is a valid result — the caller checks for
// it, the same way it already did before this flag parsing existed — so that
// "scan --fail-on high" with no target reads as "no target", not as an
// unrelated parse failure.
func parseScanArgs(args []string) (target string, opts scancmd.Options, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--fail-on":
			i++
			if i >= len(args) {
				return "", scancmd.Options{}, fmt.Errorf("--fail-on requires a value")
			}
			if err := setFailOn(&opts, args[i]); err != nil {
				return "", scancmd.Options{}, err
			}

		case strings.HasPrefix(a, "--fail-on="):
			if err := setFailOn(&opts, strings.TrimPrefix(a, "--fail-on=")); err != nil {
				return "", scancmd.Options{}, err
			}

		case a == "--fail-on-unknown":
			opts.FailOnUnknown = true

		// D48. Beside --fail-on-unknown because it is the same shape of ask:
		// a property of the finding that no severity threshold can express.
		case a == "--fail-on-unfixable":
			opts.FailOnUnfixable = true

		case a == "--fail-on-incomplete":
			opts.FailOnIncomplete = true

		// D36. The valued form narrows the gate to what the caller can act on.
		// "any" is spelled out as well as being the default, so a pipeline can
		// say which it means rather than relying on the bare form continuing to
		// mean the broad one.
		case strings.HasPrefix(a, "--fail-on-incomplete="):
			switch v := strings.TrimPrefix(a, "--fail-on-incomplete="); v {
			case "any":
				opts.FailOnIncomplete = true
			case "target":
				opts.FailOnIncompleteTarget = true
			default:
				return "", scancmd.Options{}, fmt.Errorf(
					"--fail-on-incomplete: unknown scope %q (want any or target)", v)
			}

		case a == "--output":
			i++
			if i >= len(args) {
				return "", scancmd.Options{}, fmt.Errorf("--output requires a value")
			}
			if err := setOutput(&opts, args[i]); err != nil {
				return "", scancmd.Options{}, err
			}

		case strings.HasPrefix(a, "--output="):
			if err := setOutput(&opts, strings.TrimPrefix(a, "--output=")); err != nil {
				return "", scancmd.Options{}, err
			}

		case a == "--explain":
			i++
			if i >= len(args) {
				return "", scancmd.Options{}, fmt.Errorf("--explain requires a value")
			}
			if err := setExplain(&opts, args[i]); err != nil {
				return "", scancmd.Options{}, err
			}

		case strings.HasPrefix(a, "--explain="):
			if err := setExplain(&opts, strings.TrimPrefix(a, "--explain=")); err != nil {
				return "", scancmd.Options{}, err
			}

		case strings.HasPrefix(a, "-"):
			return "", scancmd.Options{}, fmt.Errorf("unknown flag %q", a)

		default:
			if target != "" {
				return "", scancmd.Options{}, fmt.Errorf(
					"unexpected argument %q: scan takes exactly one target (already have %q)", a, target)
			}
			target = a
		}
	}

	// The two renderers are mutually exclusive, not last-one-wins, and that
	// holds for EITHER value of --output: an explicit `--output table
	// --explain X` is just as much a request for two renderers at once as
	// `--output json --explain X` is, and letting --explain silently win
	// over an explicitly requested table would be the same "flag parsed,
	// then ignored" shape --fail-on's repeat-rejection already guards
	// against, one level over. Checking only for "json" here previously let
	// `--output table --explain X` through silently — scancmd.Run's dispatch
	// says "Three renderers, exactly one chosen", and the parser is the only
	// place that can make that true rather than merely asserted.
	if opts.Explain != "" && opts.Output != "" {
		return "", scancmd.Options{}, fmt.Errorf(
			"--explain cannot be combined with --output %s: pick one renderer", opts.Output)
	}
	return target, opts, nil
}

// setOutput validates value and stores it on opts.Output, the same
// once-only, both-spellings-shared shape as setFailOn: a repeat is rejected
// rather than silently switching renderers mid-flag-list, and an
// unsupported format names what IS accepted rather than leaving the flag
// silently inert.
func setOutput(opts *scancmd.Options, value string) error {
	if opts.Output != "" {
		return fmt.Errorf("--output given more than once (already %q)", opts.Output)
	}
	switch strings.ToLower(value) {
	case "table", "json":
		opts.Output = strings.ToLower(value)
		return nil
	default:
		return fmt.Errorf("invalid output format %q: want one of table, json", value)
	}
}

// setExplain validates value and stores it on opts.Explain. A repeat is
// rejected for the same reason a repeated --fail-on is: a second
// `--explain` silently overriding the first would explain a different
// advisory than the one the user thought they asked for.
func setExplain(opts *scancmd.Options, value string) error {
	if opts.Explain != "" {
		return fmt.Errorf("--explain given more than once (already %q)", opts.Explain)
	}
	if value == "" {
		return fmt.Errorf("--explain requires a non-empty advisory id")
	}
	opts.Explain = value
	return nil
}

// setFailOn validates value and stores it on opts.FailOn, shared by both the
// "--fail-on value" and "--fail-on=value" spellings so the repeat-rejection
// and parsing logic exist in exactly one place rather than copy-pasted
// across both — two copies being "one more place for them to drift apart"
// is the same reasoning that removed the redundant len(args) < 2 guard
// above.
//
// A repeat is rejected rather than silently taking the last value:
// `--fail-on critical --fail-on low` quietly loosening the gate is the same
// "the user thought they set a threshold but did not" shape ParseBand's own
// error exists to prevent.
func setFailOn(opts *scancmd.Options, value string) error {
	if opts.FailOn != nil {
		return fmt.Errorf("--fail-on given more than once (already %q)", opts.FailOn.String())
	}
	b, err := severity.ParseBand(value)
	if err != nil {
		return err
	}
	opts.FailOn = &b
	return nil
}
