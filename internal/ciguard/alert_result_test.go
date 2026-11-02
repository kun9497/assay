package ciguard

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// QA 2026-11-02 #19: the alert job of db-publish.yml, db-sign.yml and
// db-backfill.yml handed scripts/ops-alert.sh
//
//	(needs.X.result == 'success' && needs.status.result == 'failure') && 'failure' || needs.X.result
//
// which reads a CANCELLED status job as success: the watched job passed, the
// status job hung (it had no timeout-minutes, so GitHub cancelled it at 360
// minutes) or a person stopped it, and the alert then closed and unpinned the
// failure issue although status.json was never refreshed -- while
// ops-alert.sh's own header says a cancelled job is a failure. The status job
// is `skipped` only when the watched job was, and then the first conjunct is
// already false, so `!= 'success'` is the whole fix.
//
// Held here, from the YAML, because the expression is the one piece of the
// D138 verdict that scripts/ops_alert_test.sh cannot see: the script receives
// the result the expression already decided.

// ghAlertWorkflow is the slice of a workflow this guard reads.
type ghAlertWorkflow struct {
	Jobs map[string]struct {
		Needs   needsList `yaml:"needs"`
		Timeout int       `yaml:"timeout-minutes"`
		Steps   []ghStep  `yaml:"steps"`
	} `yaml:"jobs"`
}

// needsList accepts `needs: x` and `needs: [x, y]`, both of which Actions
// allows, so neither spelling escapes the check as a parse error.
type needsList []string

func (n *needsList) UnmarshalYAML(node *yaml.Node) error {
	var one string
	if err := node.Decode(&one); err == nil {
		*n = needsList{one}
		return nil
	}
	var many []string
	if err := node.Decode(&many); err != nil {
		return err
	}
	*n = many
	return nil
}

// resultEnvLine is the raw-text shape of a RESULT env entry carrying an
// expression, for the count the parse is held to.
var resultEnvLine = regexp.MustCompile(`(?m)^\s*RESULT:\s*\$\{\{`)

// alertResultProblems checks one workflow file's source and returns its
// problems and the number of RESULT env entries it judged.
func alertResultProblems(file string, src []byte) ([]string, int, error) {
	var wf ghAlertWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", file, err)
	}
	var out []string
	// The two D138 jobs, found by the script each runs rather than by name,
	// so a renamed job is still judged.
	statusJob, alertJob := "", ""
	for _, j := range slices.Sorted(maps.Keys(wf.Jobs)) {
		for _, s := range wf.Jobs[j].Steps {
			if strings.Contains(s.Run, "scripts/publish-status.sh") {
				statusJob = j
			}
			if strings.Contains(s.Run, "scripts/ops-alert.sh") {
				alertJob = j
			}
		}
	}
	judged := 0
	resultOf := func(j string) (string, bool) {
		for _, s := range wf.Jobs[j].Steps {
			if v, ok := s.Env["RESULT"]; ok {
				judged++
				return strings.TrimSpace(v), true
			}
		}
		return "", false
	}
	if alertJob != "" {
		alert := wf.Jobs[alertJob]
		got, ok := resultOf(alertJob)
		if !ok {
			out = append(out, fmt.Sprintf("%s: job %s: runs ops-alert.sh with no RESULT env entry", file, alertJob))
		}
		var want string
		switch {
		case statusJob == "":
			if len(alert.Needs) != 1 {
				out = append(out, fmt.Sprintf("%s: job %s: needs %v; with no status job it must need exactly the job it watches", file, alertJob, []string(alert.Needs)))
				break
			}
			want = fmt.Sprintf("${{ needs.%s.result }}", alert.Needs[0])
		default:
			status := wf.Jobs[statusJob]
			if status.Timeout <= 0 {
				out = append(out, fmt.Sprintf("%s: job %s: has no timeout-minutes: a hung status job is cancelled only at GitHub's 360-minute cap, and reaches the alert as `cancelled`", file, statusJob))
			}
			if len(status.Needs) != 1 {
				out = append(out, fmt.Sprintf("%s: job %s: needs %v; the status job must need exactly the job it reports on", file, statusJob, []string(status.Needs)))
				break
			}
			watched := status.Needs[0]
			if !slices.Contains(alert.Needs, watched) || !slices.Contains(alert.Needs, statusJob) {
				out = append(out, fmt.Sprintf("%s: job %s: needs %v, must need both %s and %s", file, alertJob, []string(alert.Needs), watched, statusJob))
			}
			// A status job that did not succeed -- failure, or cancelled by
			// its timeout or a hand -- left status.json stale, which is a
			// failure to alert on. `skipped` happens only when the watched
			// job was skipped, and then the first conjunct is false.
			want = fmt.Sprintf("${{ (needs.%s.result == 'success' && needs.%s.result != 'success') && 'failure' || needs.%s.result }}", watched, statusJob, watched)
			if sgot, ok := resultOf(statusJob); ok && sgot != fmt.Sprintf("${{ needs.%s.result }}", watched) {
				out = append(out, fmt.Sprintf("%s: job %s: RESULT is `%s`, want `${{ needs.%s.result }}`", file, statusJob, sgot, watched))
			}
		}
		if ok && want != "" && got != want {
			out = append(out, fmt.Sprintf("%s: job %s: RESULT is `%s`, want `%s` (a status job that was cancelled is not a success: ops-alert.sh would close the pinned issue on a run whose status.json was never refreshed)", file, alertJob, got, want))
		}
	}
	// The parse judges the RESULT entries of the two D138 jobs. One anywhere
	// else -- a third job, a job-level env -- is missed, not passed.
	if raw := len(resultEnvLine.FindAll(src, -1)); raw != judged {
		out = append(out, fmt.Sprintf("%s: %d RESULT env entries in the text, %d judged in the status and alert jobs", file, raw, judged))
	}
	return out, judged, nil
}

func TestEveryOpsAlertReadsACancelledStatusJobAsAFailure(t *testing.T) {
	dir := filepath.Join(repoRoot, ".github", "workflows")
	files, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	perFile := map[string]int{}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		got, n, err := alertResultProblems(filepath.Base(f), src)
		if err != nil {
			t.Fatal(err)
		}
		perFile[filepath.Base(f)] = n
		for _, p := range got {
			t.Error(p)
		}
	}
	// The three workflows with a status job judge two RESULT entries each;
	// the two without, one. Without this a parse that found no job would
	// pass every workflow.
	for f, want := range map[string]int{
		"db-publish.yml": 2, "db-sign.yml": 2, "db-backfill.yml": 2,
		"scanner-diff.yml": 1, "release.yml": 1,
	} {
		if perFile[f] != want {
			t.Errorf("%s: judged %d RESULT entries, want %d", f, perFile[f], want)
		}
	}
}

// The check against workflows it must reject, one defect per row. The first
// rejected row is the expression the three workflows carried before the fix.
func TestAlertResultGuardRejects(t *testing.T) {
	const head = "on: push\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make build\n"
	status := func(timeout string) string {
		return "  status:\n    needs: [publish]\n    if: always() && needs.publish.result != 'skipped'\n    runs-on: ubuntu-latest\n" + timeout +
			"    steps:\n      - env:\n          RESULT: ${{ needs.publish.result }}\n        run: sh scripts/publish-status.sh db-publish \"$RESULT\" u\n"
	}
	alert := func(needs, result string) string {
		return "  alert:\n    needs: " + needs + "\n    if: always()\n    runs-on: ubuntu-latest\n" +
			"    steps:\n      - env:\n          RESULT: " + result + "\n        run: sh scripts/ops-alert.sh db-publish \"$RESULT\" u\n"
	}
	const fixed = "${{ (needs.publish.result == 'success' && needs.status.result != 'success') && 'failure' || needs.publish.result }}"
	const before = "${{ (needs.publish.result == 'success' && needs.status.result == 'failure') && 'failure' || needs.publish.result }}"
	wrongResult := func(got string) string {
		return "t.yml: job alert: RESULT is `" + got + "`, want `" + fixed + "` (a status job that was cancelled is not a success: ops-alert.sh would close the pinned issue on a run whose status.json was never refreshed)"
	}
	cases := []struct {
		name   string
		src    []byte
		judged int
		want   []string
	}{
		{"well formed", []byte(head + status("    timeout-minutes: 15\n") + alert("[publish, status]", fixed)), 2, nil},
		{"needs as a scalar", []byte(head + strings.Replace(status("    timeout-minutes: 15\n"), "needs: [publish]", "needs: publish", 1) + alert("[publish, status]", fixed)), 2, nil},
		{"the expression before the fix", []byte(head + status("    timeout-minutes: 15\n") + alert("[publish, status]", before)), 2, []string{wrongResult(before)}},
		{"status result ignored", []byte(head + status("    timeout-minutes: 15\n") + alert("[publish, status]", "${{ needs.publish.result }}")), 2, []string{
			wrongResult("${{ needs.publish.result }}"),
		}},
		{"status job without a timeout", []byte(head + status("") + alert("[publish, status]", fixed)), 2, []string{
			"t.yml: job status: has no timeout-minutes: a hung status job is cancelled only at GitHub's 360-minute cap, and reaches the alert as `cancelled`",
		}},
		{"alert does not wait for status", []byte(head + status("    timeout-minutes: 15\n") + alert("[publish]", fixed)), 2, []string{
			"t.yml: job alert: needs [publish], must need both publish and status",
		}},
		{"status job's own RESULT is not the watched job's", []byte(head + strings.Replace(status("    timeout-minutes: 15\n"), "RESULT: ${{ needs.publish.result }}", "RESULT: ${{ job.status }}", 1) + alert("[publish, status]", fixed)), 2, []string{
			"t.yml: job status: RESULT is `${{ job.status }}`, want `${{ needs.publish.result }}`",
		}},
		// No status job: the alert passes the watched job's result through.
		{"no status job, plain result", []byte(head + alert("[publish]", "${{ needs.publish.result }}")), 1, nil},
		{"no status job, wrong job named", []byte(head + alert("[publish]", "${{ needs.diff.result }}")), 1, []string{
			"t.yml: job alert: RESULT is `${{ needs.diff.result }}`, want `${{ needs.publish.result }}` (a status job that was cancelled is not a success: ops-alert.sh would close the pinned issue on a run whose status.json was never refreshed)",
		}},
		// A RESULT entry the parse never judges -- here at job level in a
		// job running neither script -- is reported, not passed.
		{"RESULT outside the two jobs", []byte(head + status("    timeout-minutes: 15\n") + alert("[publish, status]", fixed) +
			"  other:\n    runs-on: ubuntu-latest\n    env:\n      RESULT: ${{ needs.publish.result }}\n    steps:\n      - run: echo \"$RESULT\"\n"), 2, []string{
			"t.yml: 3 RESULT env entries in the text, 2 judged in the status and alert jobs",
		}},
		{"no alert job at all", []byte(head), 0, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, n, err := alertResultProblems("t.yml", c.src)
			if err != nil {
				t.Fatal(err)
			}
			if n != c.judged {
				t.Errorf("judged %d RESULT entries, want %d", n, c.judged)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("problems = %q\nwant       %q", got, c.want)
			}
		})
	}
}
