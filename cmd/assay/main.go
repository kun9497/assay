// Command assay is an SBOM-driven vulnerability scanner.
//
// See https://github.com/kun9497/assay for design notes and roadmap.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/dbcmd"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/provider/nvd"
	"github.com/kun9497/assay/internal/provider/osv"
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
  db update       Build or refresh the local vulnerability database
  db status       Show what is in the database and how current it is
  version         Print version information
  help            Show this help

Scan flags (any order, before or after the target):
  --fail-on <band>      Exit 1 if a finding is at or above <band>
                        (none, low, medium, high, critical)
  --fail-on-unknown     Exit 1 if a finding's severity could not be rated
  --fail-on-incomplete  Exit 2 if any package's evaluation was incomplete
  --output <format>     table (default) or json
  --explain <id>        Print one advisory's full Evidence (its own ID, or
                        any alias/upstream identifier) instead of the report
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
			fmt.Fprintln(stderr, "error: db requires a subcommand (update, status)")
			return exitError
		}
		path, err := store.DefaultPath()
		if err != nil {
			fmt.Fprintf(stderr, "error: locate database: %v\n", err)
			return exitError
		}
		switch args[1] {
		case "update":
			return dbcmd.Update(context.Background(), path,
				[]provider.Provider{osv.New(osv.Ecosystems, "")},
				dbUpdateAnnotators(),
				stdout, stderr)
		case "status":
			return dbcmd.Status(path, stdout, stderr)
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
// days, using NVD's own lastModStartDate filter. Absent or unparseable means
// the whole feed.
//
// It is an environment variable rather than a flag because it is a property of
// how this database is being maintained, not of one invocation: a builder runs
// a full pass once and incremental passes daily, and mixing the two by hand on
// the command line is how a database ends up with a gap nobody notices. A flag
// can come later if anyone wants one.
//
// Measured 2026-08-03, and the reason this exists: a full pass is about seven
// hours, because NVD generates each 2,000-record page in 114-136 seconds
// whatever the page size or compression. The rate-limit pauses are 20 minutes
// of that. Above 120 days the API rejects the window outright, so the value is
// capped here rather than sent and refused.
func nvdOptionsFromEnv() nvd.Options {
	opts := nvd.Options{APIKey: os.Getenv("NVD_API_KEY")}
	if raw := os.Getenv("NVD_SINCE_DAYS"); raw != "" {
		if days, err := strconv.Atoi(raw); err == nil && days > 0 {
			if days > 120 {
				days = 120
			}
			opts.Since = time.Now().UTC().AddDate(0, 0, -days)
		}
	}
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

// dbUpdateAnnotators is every provider.Annotator `db update` runs, built
// from the environment. Pulled out of the "update" case as its own function
// so a test can call it directly and inspect what reaches newNVDAnnotator.
func dbUpdateAnnotators() []provider.Annotator {
	return []provider.Annotator{newNVDAnnotator(nvdOptionsFromEnv())}
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

		case a == "--fail-on-incomplete":
			opts.FailOnIncomplete = true

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
