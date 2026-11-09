// Command truthset measures assay's precision and recall against a committed
// set of LABELLED verdicts (D161): one row per (installed package, CVE) whose
// expected answer -- affected with this fixed version, affected with no fix,
// or clean -- is the distro's own published statement, recorded with where it
// was read and when. It is the ground-truth half the weekly differential
// (cmd/scandiff, D93) is not: agreement with grype is a proxy that shares
// assay's upstreams, so a feed error both read is invisible to it, and its
// tuple carries no version and no fix state, so it cannot test the
// fixed-version boundary. This tool can, and it says so with a confidence
// interval rather than a count.
//
// Each label's package is scanned the way a customer's SBOM path scans it --
// a one-component CycloneDX document carrying the purl the image path would
// spell (D121) -- so the whole chain from purl to verdict is under test
// against the pulled, signed database, with no network call in the scan
// (D14). Labels with class "data" name known data gaps (a frozen key whose
// upstream fix came after the freeze, D110); they are judged and printed, and
// kept out of the metrics so a precision figure says what the MATCHER does
// with the data it has.
//
// It is a separate `package main` under cmd/, not shipped by `make build`,
// stdlib-only, with scandiff's shape: run(args, stdout, stderr, exec) is the
// testable seam and main only translates its return into os.Exit.
package main

import (
	"bytes"
	"os"
	"os/exec"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, realExec))
}

// realExec is the only place this package touches os/exec; tests supply a
// fake through run's execScan parameter. The child's stderr goes straight
// to ours (diagnostics stay diagnostics); only stdout -- the JSON this tool
// parses -- is captured.
func realExec(bin string, args ...string) ([]byte, int, error) {
	cmd := exec.Command(bin, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return stdout.Bytes(), ee.ExitCode(), nil
		}
		return stdout.Bytes(), -1, err
	}
	return stdout.Bytes(), 0, nil
}
