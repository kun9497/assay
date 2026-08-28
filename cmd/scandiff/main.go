// Command scandiff is the D93 differential, extended by D105 to a second
// comparison scanner: it institutionalizes the check that caught D90, a
// production regression the ad hoc manual comparison had already been
// catching by hand for several slices before anyone wired it into CI.
//
// It runs the same target through assay and one or two other scanners
// (grype always; trivy where a target's entry opts in), reduces each side's
// output to a set of (package, CVE) tuples, and judges the result against a
// COMMITTED FLOORS FILE (.github/scanner-diff-targets.json) rather than an
// exact snapshot: assay's own database changes every week (new advisories,
// corrected fixed-versions, a provider gaining a distro), so a byte-for-byte
// comparison against last week's answer would need updating every single
// run and would very quickly stop being read. A floor only trips when a
// number gets WORSE than the worst it has ever been asked to tolerate --
// agreement with grype (or trivy) collapses, assay's own finding count
// drops or explodes, or packages start going unevaluated that did not
// before. It is silent otherwise, on purpose: the tools are expected to
// diverge (their data sources differ), and report-only would have been
// exactly as silent as no check at all the day D90 happened, because nobody
// was reading it.
//
// Trivy's own floors are OPTIONAL per target (D105): it does not cover
// every distro assay does, and a fresh target's trivy floors start out
// INFORMATIONAL -- an empty "trivy" block measures and prints the numbers
// without ever breaching -- until a human commits real ones. See
// run.go's trivyPhase and targets.go's TrivyFloors for the mechanics.
//
// It is a separate `package main` under cmd/, not shipped by `make build`:
// CI builds it ad hoc (`go build ./cmd/scandiff`) the same way it builds
// ./cmd/assay, and it is stdlib-only -- the three-direct-dependency rule
// (see CLAUDE.md's Conventions) is a real constraint on the module as a
// whole, and this tool needs none of the three to do its job.
package main

import (
	"bytes"
	"os"
	"os/exec"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, realExec))
}

// realExec is the only place this package touches os/exec. A test never
// reaches it -- run's execScan parameter exists precisely so tests supply a
// fake instead (see run.go's execFunc doc comment).
//
// The child's stderr is wired straight to our own stderr (diagnostics stay
// diagnostics, per the repo's stream discipline) rather than captured: a
// scan's own progress output belongs in the CI log live, not buffered up
// and printed after the fact. Only stdout is captured, because that is the
// JSON this tool actually parses.
func realExec(bin string, args ...string) ([]byte, int, error) {
	cmd := exec.Command(bin, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// The process ran and exited nonzero -- that is data (an assay
			// exit 2, a grype or trivy hard failure), not a failure to
			// launch it, so it comes back through exitCode with a nil error.
			return stdout.Bytes(), exitErr.ExitCode(), nil
		}
		// Could not even start it: wrong path, no permission, and so on.
		return stdout.Bytes(), -1, err
	}
	return stdout.Bytes(), 0, nil
}
