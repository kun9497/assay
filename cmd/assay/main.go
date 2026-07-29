// Command assay is an SBOM-driven vulnerability scanner.
//
// See https://github.com/kun9497/assay for design notes and roadmap.
package main

import (
	"fmt"
	"io"
	"os"
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
  scan <target>   Scan an SBOM file, directory, or container image
  version         Print version information
  help            Show this help
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
		if len(args) < 2 {
			fmt.Fprintln(stderr, "error: scan requires a target")
			fmt.Fprint(stderr, usage)
			return exitError
		}
		return scan(args[1], stdout, stderr)

	default:
		fmt.Fprintf(stderr, "error: unknown command %q\n", args[0])
		fmt.Fprint(stderr, usage)
		return exitError
	}
}

// scan is the pipeline entry point: resolve target -> catalog packages ->
// match against the vulnerability DB -> report.
//
// TODO: implement. Returning exitError is deliberate — an unimplemented
// scanner must never report a clean result.
func scan(target string, stdout, stderr io.Writer) int {
	fmt.Fprintf(stderr, "error: scanning is not implemented yet (target %q)\n", target)
	return exitError
}
