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
	"github.com/kun9497/assay/internal/provider/amazon"
	"github.com/kun9497/assay/internal/provider/fedora"
	"github.com/kun9497/assay/internal/provider/knvd"
	"github.com/kun9497/assay/internal/provider/nvd"
	"github.com/kun9497/assay/internal/provider/oracle"
	"github.com/kun9497/assay/internal/provider/osv"
	"github.com/kun9497/assay/internal/provider/redhat"
	"github.com/kun9497/assay/internal/provider/suse"
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
  --fail-on-unfixable[=any|wont-fix]
                        Exit 1 if a finding has no fix available from any
                        source - the vendor says the package is affected and
                        will not be fixed, or nobody recorded a version to
                        move to. Reported and counted either way; this makes
                        it fail the build. =wont-fix narrows it to the ones a
                        vendor has said will never be fixed, where waiting is
                        not a strategy.
  --fail-on-incomplete[=any|target]
                        Exit 2 if any package's evaluation was incomplete.
                        =target narrows it to causes you can act on (a version
                        in the scanned artifact that will not parse), leaving
                        out malformed advisory data you cannot fix.
  --db-max-age=<dur>    Exit 2 if the vulnerability data is older than <dur>
                        (24h, 168h). Measured from the UPSTREAM data, not from
                        when the database was built, so a mirror serving a stale
                        snapshot does not read as fresh. Off by default.
  --output <format>     table (default), json, or sarif
                        sarif is SARIF 2.1.0 for GitHub code scanning. Packages
                        that could not be evaluated are emitted as note-level
                        results as well as tool notifications, because a partial
                        scan must not read as a complete one (D55).
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
  --ratings-only  Skip the advisory providers entirely and carry the seed's
                  advisories forward VERBATIM (a file copy, not a rebuild),
                  re-running only the rating annotators below. Requires
                  --seed. Exists for a D65 backfill slice, whose whole point
                  is the NVD window alone -- without this every slice paid
                  for rebuilding OSV (~54min) and Red Hat (~21min) too.
                  An advisory withdrawn upstream since the seed was built
                  survives until the next full build: fine for a seed at
                  most a day old, wrong for anything older.

Environment (db build only — a scan reads no environment and no network):
  NVD_ENABLE=1          Also fetch NIST's CVSS scores, so findings whose
                        advisory carries no severity can still be rated.
                        Off by default: a full pass takes about seven hours.
  NVD_SINCE_DAYS=<n>    Bound that fetch to CVEs modified in the last n days
                        (max 120). Bounds ONE BUILD, not a delta on the last
                        one — db status prints the window it covered.
  NVD_UNTIL_DAYS=<n>    Close that window n days ago, so a backfill can walk
                        the feed in slices (D65). Needs NVD_SINCE_DAYS, and
                        the slices only extend claimed coverage in order —
                        see the README's "Backfilling older ratings".
  NVD_API_KEY=<key>     Raise NVD's rate limit tenfold. Optional, and it does
                        not shorten the seven hours; NVD's own response
                        generation is the bottleneck, not the pacing.
  REDHAT_ENABLE=0       Skip Red Hat's CSAF VEX feed. ON BY DEFAULT (D51): it
                        is the only source that can say a RHEL package is
                        affected and WILL NOT BE FIXED, and the published
                        artifact carries it, so a build without it produces a
                        narrower database than db update delivers.
                        Set this to 0 for a local build that does not scan RHEL
                        and wants to be about twenty minutes shorter.
  AMAZON_ENABLE=0       Skip Amazon Linux's ALAS feed (AL2 core+extras and AL2023 core). ON BY
                        DEFAULT (D73, D78), for the same reason as Red Hat: the published
                        artifact carries it, so a build without it produces a narrower database
                        than db update delivers.
                        AL2's 73 extras topics (D78) are fetched alongside core -- docker, ecs,
                        livepatch, nitro-enclaves, firefox and more. AL2023's NVIDIA and
                        livepatch repos are NOT fetched: 306 + 286 advisories live outside
                        AL2023 core in a different repo layout, so a package installed from
                        either is evaluated only against AL2023 core data.
                        Set this to 0 for a local build that does not scan Amazon Linux.
  ORACLE_ENABLE=0       Skip Oracle Linux's OVAL feed (ELSA/ELBA errata,
                        Oracle Linux 5-10). ON BY DEFAULT (D74), for the
                        same reason as Red Hat and Amazon Linux: the
                        published artifact carries it, so a build without
                        it produces a narrower database than db update
                        delivers. The archive is one 12 MB unauthenticated
                        file, so this does not shorten a build the way
                        REDHAT_ENABLE=0 does.
                        Set this to 0 for a local build that does not scan
                        Oracle Linux.
  FEDORA_ENABLE=0       Skip Fedora's Bodhi updates feed (F43 and F44, its
                        current stable releases). ON BY DEFAULT (D75), for
                        the same reason as Red Hat, Amazon Linux and Oracle
                        Linux: the published artifact carries it, so a build
                        without it produces a narrower database than
                        db update delivers.
                        CURRENT RELEASES ONLY: Fedora's ~13-month support
                        window means an EOL'd release (F42 archived
                        2026-05-27) gets no new advisories from this feed
                        ever again, so a scan of an EOL'd Fedora image is a
                        frozen lower bound with no in-band signal that it
                        stopped moving. Severity also has no CVSS vector
                        anywhere in this feed -- only Bodhi's own
                        urgent/high/medium/low word, with the NVD join
                        carrying the rest -- and CVE linkage is extracted
                        from free-text prose rather than a structured field,
                        which is a measured 18.3% miss rate that is counted
                        rather than hidden.
                        Set this to 0 for a local build that does not scan
                        Fedora.
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
			// Parsed independently of resolveBuildSeed below: --ratings-only
			// is a bare boolean, not a "consume the next token" flag like
			// --seed, so scanning for it once and then stripping it out is
			// simpler than teaching resolveBuildSeed's position-locked
			// parsing (args[2]/args[3], unchanged since before this flag
			// existed -- readme_schema_test.go calls it directly) a second
			// flag shape. See resolveRatingsOnly's own doc comment.
			ratingsOnly := resolveRatingsOnly(args)
			ref, hasSeed, ok := resolveBuildSeed(withoutRatingsOnly(args), stderr)
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
				// dbcmd.PullSeed, not dbcmd.Pull: a --seed input tolerates a
				// schema one behind this binary's (D67's own seed contract)
				// and retries once against the previous schema's tag on a
				// MANIFEST_UNKNOWN (D-seed-bootstrap, symmetric with push.go's
				// D60) -- the failure the scheduled builder hit on the day a
				// new schema's tag had never been pushed to yet. `db update`
				// keeps using Pull's exact match; only a --seed input is safe
				// to loosen (see PullSeed's own doc comment for why).
				//
				// Its own exit code and stderr already explain what went
				// wrong. Returning it as-is (never falling through to build
				// from empty) is Task 5's whole point: the scheduled builder
				// passes --seed every night, so a registry outage must fail
				// loudly rather than quietly publish a one-day database over
				// a complete one.
				if code := dbcmd.PullSeed(context.Background(), seedPath, ref, stdout, stderr); code != 0 {
					return code
				}
			}
			// ref is what the disclosure names the seed as -- the original
			// reference, not seedPath's scratch file above, which an
			// archived CI log would not recognize.
			return dbcmd.Update(context.Background(), path, seedPath, ref, ratingsOnly,
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
	if err != nil || days <= 0 {
		fmt.Fprintf(stderr, "warning: NVD_SINCE_DAYS=%q is not a positive number of days; syncing the whole feed\n", raw)
		return opts
	}

	untilDays := nvdUntilDaysFromEnv(stderr)
	// Inverted (or empty) windows are refused at DAY granularity, on the
	// integers, before any clock is read. The first version compared two
	// time.Time values and was wrong twice for it: once when the two ends
	// came from separate clock readings (equal days inverted by microseconds,
	// caught by CI on Linux only), and once when the pre-D65 SINCE cap ran
	// first -- NVD_SINCE_DAYS=240 was capped to 120, which made
	// NVD_UNTIL_DAYS=120 read as inverted, and the two warnings COMPOSED into
	// a [120d, now] window nobody asked for. The 2026-08-14 backfill slice
	// ran exactly that window. (It happened to be the most useful window in
	// the feed and recovered the ratings anyway, which is luck, not design.)
	if untilDays >= 0 && untilDays >= days {
		fmt.Fprintf(stderr,
			"warning: NVD_UNTIL_DAYS=%d is not after NVD_SINCE_DAYS; the window ends now\n", untilDays)
		untilDays = -1
	}

	// The API's 120-day maximum is on the WIDTH of the window, not on how far
	// back it starts -- lastModStartDate to lastModEndDate may span at most
	// 120 days, wherever they sit. Capping SINCE alone predates D65, when the
	// end was always "now" and the two were the same thing; kept as-is it
	// made every slice deeper than 120 days unrepresentable, and the runbook
	// [240,120] slice impossible.
	floor := 0
	if untilDays > 0 {
		floor = untilDays
	}
	if days-floor > 120 {
		if untilDays > 0 {
			fmt.Fprintf(stderr,
				"warning: NVD_SINCE_DAYS=%d with NVD_UNTIL_DAYS=%d spans more than the API's 120-day maximum window; using %d\n",
				days, untilDays, floor+120)
		} else {
			fmt.Fprintf(stderr,
				"warning: NVD_SINCE_DAYS=%d exceeds the API's 120-day maximum window; using 120\n", days)
		}
		days = floor + 120
	}

	// One clock reading for both ends -- see clockNow.
	now := clockNow()
	opts.Since = now.AddDate(0, 0, -days)
	if untilDays > 0 {
		opts.Until = now.AddDate(0, 0, -untilDays)
	}
	return opts
}

// nvdUntilDaysFromEnv reads NVD_UNTIL_DAYS as a day count, -1 when unset or
// unusable. The window arithmetic it feeds lives in nvdOptionsFromEnv above,
// on integers -- this only answers "what number did the environment carry".
//
// A negative count is days in the FUTURE: AddDate flips its sign, the
// inverted-window check passes (a future end IS after since), and CoversUntil
// then records a date that has not happened -- coverage claimed for time that
// does not exist yet. Refused at parse, like the SINCE side.
func nvdUntilDaysFromEnv(stderr io.Writer) int {
	raw := os.Getenv("NVD_UNTIL_DAYS")
	if raw == "" {
		return -1
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days < 0 {
		fmt.Fprintf(stderr, "warning: NVD_UNTIL_DAYS=%q is not a number of days; the window ends now\n", raw)
		return -1
	}
	return days
}

// clockNow is a seam so a test can inject a clock that ADVANCES between
// calls. That is not a convenience: the defect it guards against is two ends
// of one window read from two clock calls, which Windows' coarse clock hides
// (both calls return the same reading) and Linux's nanosecond one exposes --
// the shape CI caught on 2026-08-14 after the local suite passed. A test
// using the real clock inherits whichever platform it runs on; one injecting
// an advancing clock fails on the defect everywhere.
var clockNow = func() time.Time { return time.Now().UTC() }

// nvdUntilFromEnv reads NVD_UNTIL_DAYS, the LATE end of the window, in days
// before now (D65).
//
// It exists for one operation: restoring ratings for records nobody has
// modified recently. Every window before this ran to the present, so
// re-running could never reach them however far back Since was set --
// NVD_SINCE_DAYS=120 and NVD_SINCE_DAYS=365 both end today and both cost a
// full pass. A backfill instead walks CLOSED ranges backwards, one per run,
// and each run publishes, so the artifact is the checkpoint.
//
// Ignored when no Since was given: an end with no start is a window running
// from 1999 to a date in the past, which is the seven-hour pass with extra
// steps rather than the bounded slice the caller was reaching for.
func nvdUntilFromEnv(stderr io.Writer, now time.Time, since time.Time) time.Time {
	raw := os.Getenv("NVD_UNTIL_DAYS")
	if raw == "" {
		return time.Time{}
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days < 0 {
		fmt.Fprintf(stderr, "warning: NVD_UNTIL_DAYS=%q is not a number of days; the window ends now\n", raw)
		return time.Time{}
	}
	until := now.AddDate(0, 0, -days)
	// A window that ends before it starts asks for nothing, and NVD answers
	// an inverted range with a 404 rather than an empty page -- an hour into
	// a build, having said nothing about why.
	if !until.After(since) {
		fmt.Fprintf(stderr,
			"warning: NVD_UNTIL_DAYS=%d is not after NVD_SINCE_DAYS; the window ends now\n", days)
		return time.Time{}
	}
	return until
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

// newAmazonProvider constructs the Amazon Linux ALAS provider. A package
// variable for the same reason newRedHatProvider is: a test can substitute a
// spy and observe the Options that reached construction, without
// amazon.New's default repos — the live cdn.amazonlinux.com feeds — ever
// being fetched from.
var newAmazonProvider = amazon.New

// newOracleProvider constructs the Oracle Linux OVAL provider. A package
// variable for the same reason newRedHatProvider and newAmazonProvider are: a
// test can substitute a spy and observe the Options that reached
// construction, without oracle.New's default URL — the live 12 MB archive —
// ever being fetched from.
var newOracleProvider = oracle.New

// newFedoraProvider constructs the Fedora Bodhi updates provider. A package
// variable for the same reason newRedHatProvider, newAmazonProvider and
// newOracleProvider are: a test can substitute a spy and observe the
// Options that reached construction, without fedora.New's default releases
// — the live bodhi.fedoraproject.org feed — ever being fetched from.
var newFedoraProvider = fedora.New

// newSUSEProvider constructs the SUSE CSAF VEX provider (D77). A package
// variable for the same reason newRedHatProvider, newAmazonProvider,
// newOracleProvider and newFedoraProvider are: a test can substitute a spy
// and observe the Options that reached construction, without suse.New's
// default BaseURL — the live 445 MB archive — ever being fetched from.
var newSUSEProvider = suse.New

// dbUpdateProviders is every provider.Provider `db build` runs.
//
// All six are on by default. Red Hat was opt-in when it landed, on the
// grounds that it adds ~1.9 million affected entries for people who may
// never scan a RHEL image — and D51 reversed that once the published
// artifact started carrying it. Amazon Linux, Oracle Linux, Fedora and SUSE
// followed the same reasoning from the start (D73, D74, D75, D77) rather
// than repeating Red Hat's opt-in-then-reverse path: the published artifact
// is meant to carry each of them, and a default that disagreed with the
// artifact would mean `db build` and `db update` produce different
// databases, and `db push` would refuse the narrower one.
//
// REDHAT_ENABLE=0, AMAZON_ENABLE=0, ORACLE_ENABLE=0, FEDORA_ENABLE=0 and
// SUSE_ENABLE=0 still turn each off, for a local build that wants to be
// shorter and does not care about that distro.
func dbUpdateProviders(stderr io.Writer) []provider.Provider {
	// Progress goes to stderr for the same reason every provider below sends
	// theirs there: D82's Rocky Linux/AlmaLinux module-stream attachment
	// narrows what it attaches (a record with zero or 2+ summary tokens stays
	// stream-less), and a run that printed nothing about it would be
	// indistinguishable from one that was broken.
	ps := []provider.Provider{osv.New(osv.Ecosystems, "").WithProgress(stderr)}
	if envFlag(stderr, "REDHAT_ENABLE", true) {
		// Progress goes to stderr for nvd's reason: this provider discards the
		// large majority of what it reads, and a run that printed nothing
		// about it would be indistinguishable from one that was broken.
		ps = append(ps, newRedHatProvider(redhat.Options{Progress: stderr}))
	}
	if envFlag(stderr, "AMAZON_ENABLE", true) {
		// Progress goes to stderr for the same reason: Fetch's own
		// extrasDisclosure line is what keeps a core-only build from reading
		// as a complete one, and it has to land somewhere a reader sees it.
		ps = append(ps, newAmazonProvider(amazon.Options{Progress: stderr}))
	}
	if envFlag(stderr, "ORACLE_ENABLE", true) {
		// Progress goes to stderr for the same reason: the UEK/module-train
		// guard's skip counts are exactly the "silently drops part of its
		// input" case every other provider's Progress line exists for.
		ps = append(ps, newOracleProvider(oracle.Options{Progress: stderr}))
	}
	if envFlag(stderr, "FEDORA_ENABLE", true) {
		// Progress goes to stderr for the same reason: Fetch's own
		// eolDisclosure line and its NoExtractableCVE count are exactly the
		// "silently drops/narrows part of its input" case every other
		// provider's Progress line exists for.
		ps = append(ps, newFedoraProvider(fedora.Options{Progress: stderr}))
	}
	if envFlag(stderr, "SUSE_ENABLE", true) {
		// Progress goes to stderr for the same reason: this provider discards
		// the large majority of what it reads (SAP, HPC, Micro, Manager,
		// Storage and every other product sharing SLES's namespace), the
		// identical shape Red Hat's own discard line exists for.
		ps = append(ps, newSUSEProvider(suse.Options{Progress: stderr}))
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

// resolveRatingsOnly reports whether `--ratings-only` (D66) was given
// anywhere among a `db build` invocation's flags.
//
// Split out rather than folded into resolveBuildSeed above: that function's
// parsing is position-locked (args[2] must be exactly "--seed", its value
// exactly args[3]) and predates this flag -- readme_schema_test.go calls it
// directly with that exact shape, so its behaviour for "--seed <ref>" alone
// has to keep working unchanged. A bare boolean does not share --seed's
// "consume the next token as a value" shape anyway, so scanning the whole
// slice once here, independently, composes with --seed in EITHER order
// (`--ratings-only --seed <ref>` and `--seed <ref> --ratings-only` both
// work) without resolveBuildSeed ever having to know this flag exists -- see
// withoutRatingsOnly, which is what makes that true.
func resolveRatingsOnly(args []string) bool {
	if len(args) <= 2 {
		return false
	}
	for _, a := range args[2:] {
		if a == "--ratings-only" {
			return true
		}
	}
	return false
}

// withoutRatingsOnly strips every "--ratings-only" token out of a `db build`
// argument list before it reaches resolveBuildSeed, which -- per
// resolveRatingsOnly's own doc comment -- only ever expects to find "--seed
// <ref>" (or nothing) starting at args[2]. Without this, `--ratings-only`
// arriving BEFORE `--seed` would land at args[2] itself and resolveBuildSeed
// would reject it as an unknown flag, even though it is a real one.
func withoutRatingsOnly(args []string) []string {
	if len(args) <= 2 {
		return args
	}
	out := append([]string{}, args[:2]...)
	for _, a := range args[2:] {
		if a != "--ratings-only" {
			out = append(out, a)
		}
	}
	return out
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
	// The SARIF driver reports which build produced the document (D55);
	// nothing else reads it.
	opts.Version = version
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
		// D59. A duration, not a day count: CI cadences are not all daily,
		// and Go's own parser already spells 36h and 7d-equivalent 168h
		// without this inventing a unit.
		case strings.HasPrefix(a, "--db-max-age="):
			v := strings.TrimPrefix(a, "--db-max-age=")
			d, perr := time.ParseDuration(v)
			if perr != nil {
				return "", scancmd.Options{}, fmt.Errorf(
					"--db-max-age: %q is not a duration (try 24h, 168h): %w", v, perr)
			}
			// Zero disables the check, so accepting it from the command line
			// would make --db-max-age=0 look like a strict setting and be the
			// opposite. A negative one is nonsense the same way.
			if d <= 0 {
				return "", scancmd.Options{}, fmt.Errorf(
					"--db-max-age: %q must be positive; omit the flag to scan without the check", v)
			}
			opts.DBMaxAge = d

		case a == "--db-max-age":
			return "", scancmd.Options{}, fmt.Errorf(
				"--db-max-age needs a duration, e.g. --db-max-age=48h")

		case a == "--fail-on-unfixable":
			opts.FailOnUnfixable = true

		// D52. Valued exactly like --fail-on-incomplete above, and for the
		// same reason: "any" is spelled out as well as being the bare form's
		// meaning, so a pipeline that wants the broad gate can say so instead
		// of relying on the default never moving.
		case strings.HasPrefix(a, "--fail-on-unfixable="):
			switch v := strings.TrimPrefix(a, "--fail-on-unfixable="); v {
			case "any":
				opts.FailOnUnfixable = true
			case "wont-fix":
				opts.FailOnUnfixableWontFix = true
			default:
				return "", scancmd.Options{}, fmt.Errorf(
					"--fail-on-unfixable: unknown scope %q (want any or wont-fix)", v)
			}

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
	case "table", "json", "sarif":
		opts.Output = strings.ToLower(value)
		return nil
	default:
		return fmt.Errorf("invalid output format %q: want one of table, json, sarif", value)
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
