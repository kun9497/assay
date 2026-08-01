// Command assay is an SBOM-driven vulnerability scanner.
//
// See https://github.com/kun9497/assay for design notes and roadmap.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kun9497/assay/internal/dbcmd"
	"github.com/kun9497/assay/internal/provider"
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
                  tarball, or an oci-dir: layout (Go, npm, PyPI, Alpine)
  db update       Build or refresh the local vulnerability database
  db status       Show what is in the database and how current it is
  version         Print version information
  help            Show this help

Scan flags (any order, before or after the target):
  --fail-on <band>      Exit 1 if a finding is at or above <band>
                        (none, low, medium, high, critical)
  --fail-on-unknown     Exit 1 if a finding's severity could not be rated
  --fail-on-incomplete  Exit 2 if any package's evaluation was incomplete
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
				[]provider.Provider{osv.New(osv.Ecosystems, "")}, stdout, stderr)
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
	return target, opts, nil
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
