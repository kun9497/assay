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

// Follow-up to the exit-fallback guard (audit 2026-10-22 P4, closed 2026-11-02):
// the other way a step output reaches a shell is through `env:`, as
// `PUSHED: ${{ steps.push.outputs.pushed }}` does in db-publish.yml and
// db-backfill.yml. An empty output there is an empty variable, and the step
// runs on with it. For the signing step that meant cosign refusing "" three
// times and the step then reporting the artifact "pushed and UNSIGNED" --
// every db update refuses it until db-sign.yml is dispatched -- about a
// digest nobody had, when the real defect was a renamed `id: push` or a
// mistyped output name.
//
// So a step that maps a step output into env must open its run block by
// testing that variable non-empty (`[ -n "$X" ] || ...` or `${X:?...}`), and,
// as for the exit sites, the output must come from a step declared earlier in
// the same job that writes it to $GITHUB_OUTPUT.

// envStepOutput matches an env value that is exactly one step output.
var envStepOutput = regexp.MustCompile(
	`^\s*\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*\}\}\s*$`)

// envStepOutputLine is the raw-text shape of such an env entry, for the count
// the parse is held to.
var envStepOutputLine = regexp.MustCompile(
	`(?m)^\s*[A-Za-z_][A-Za-z0-9_]*:\s*\$\{\{\s*steps\.[A-Za-z0-9_-]+\.outputs\.[A-Za-z0-9_-]+\s*\}\}\s*$`)

// firstCommand returns the first line of a run block that is not blank or a
// comment: the guard has to come before any use of the variable, and "first"
// is the one position a reader can check without tracing the script.
func firstCommand(run string) string {
	for _, l := range strings.Split(run, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return t
	}
	return ""
}

func nonEmptyGuard(name string) *regexp.Regexp {
	q := regexp.QuoteMeta(name)
	return regexp.MustCompile(`^(\[\s+-n\s+"\$\{?` + q + `\}?"\s+\]|:\s*"?\$\{` + q + `:\?)`)
}

// envOutputProblems checks one workflow file's source and returns its problems
// and the number of env entries it judged.
func envOutputProblems(file string, src []byte) ([]string, int, error) {
	var wf ghWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", file, err)
	}
	var out []string
	sites := 0
	for _, j := range slices.Sorted(maps.Keys(wf.Jobs)) {
		steps := wf.Jobs[j].Steps
		for i, s := range steps {
			for _, v := range slices.Sorted(maps.Keys(s.Env)) {
				p := envStepOutput.FindStringSubmatch(s.Env[v])
				if p == nil {
					continue
				}
				sites++
				id, name := p[1], p[2]
				where := fmt.Sprintf("%s: job %s: env %s=${{ steps.%s.outputs.%s }}", file, j, v, id, name)
				if first := firstCommand(s.Run); !nonEmptyGuard(v).MatchString(first) {
					out = append(out, where+` is used before `+"`[ -n \"$"+v+"\" ]`"+` tests it: an empty output would reach the command as ""`)
				}
				producer := -1
				for k := 0; k < i; k++ {
					if steps[k].ID == id {
						producer = k
						break
					}
				}
				if producer < 0 {
					out = append(out, where+" names step id "+id+", which no earlier step in the job declares")
					continue
				}
				writes := regexp.MustCompile(`(?m)\b` + regexp.QuoteMeta(name) + `=.*>>\s*"?\$GITHUB_OUTPUT"?`)
				if !writes.MatchString(steps[producer].Run) {
					out = append(out, where+" reads output "+name+", which step "+id+" never writes to $GITHUB_OUTPUT")
				}
			}
		}
	}
	// The parse sees steps' env: blocks. The same line anywhere else (a job-level
	// env, a mis-indented step) is missed, not passed, so the text must hold no
	// more such entries than the parse judged.
	if raw := len(envStepOutputLine.FindAll(src, -1)); raw != sites {
		out = append(out, fmt.Sprintf("%s: %d env entries mapping a step output in the text, %d inside a step", file, raw, sites))
	}
	return out, sites, nil
}

func TestEveryStepOutputMappedIntoEnvIsTestedNonEmpty(t *testing.T) {
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
		got, n, err := envOutputProblems(filepath.Base(f), src)
		if err != nil {
			t.Fatal(err)
		}
		perFile[filepath.Base(f)] = n
		for _, p := range got {
			t.Error(p)
		}
	}
	// The sign and self-check steps of the two publishing workflows. Without
	// this, a pattern matching nothing would pass every workflow.
	for _, f := range []string{"db-publish.yml", "db-backfill.yml"} {
		if perFile[f] != 2 {
			t.Errorf("%s: judged %d env entries mapping a step output, want 2", f, perFile[f])
		}
	}
}

// The check against workflows it must reject, one defect per row.
func TestEnvOutputGuardRejects(t *testing.T) {
	const producer = `
      - id: push
        run: |
          out=$(./bin/assay db push | tail -n1)
          echo "pushed=$out" >> "$GITHUB_OUTPUT"
`
	consumer := func(run string) string {
		return "\n      - env:\n          PUSHED: ${{ steps.push.outputs.pushed }}\n        run: |\n" + run
	}
	wf := func(steps string) []byte {
		return []byte("on: push\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:" + steps)
	}
	const where = "t.yml: job publish: env PUSHED=${{ steps.push.outputs.pushed }}"
	cases := []struct {
		name  string
		src   []byte
		sites int
		want  []string
	}{
		{"well formed", wf(producer + consumer(
			"          # a comment first is fine\n          [ -n \"$PUSHED\" ] || { echo none; exit 2; }\n          cosign sign \"$PUSHED\"\n")), 1, nil},
		{"braced parameter form", wf(producer + consumer(
			"          : \"${PUSHED:?the Publish step recorded no digest}\"\n          cosign sign \"$PUSHED\"\n")), 1, nil},
		{"no guard", wf(producer + consumer(
			"          cosign sign \"$PUSHED\"\n")), 1, []string{
			where + ` is used before ` + "`[ -n \"$PUSHED\" ]`" + ` tests it: an empty output would reach the command as ""`,
		}},
		{"guard after the use", wf(producer + consumer(
			"          cosign sign \"$PUSHED\"\n          [ -n \"$PUSHED\" ] || exit 2\n")), 1, []string{
			where + ` is used before ` + "`[ -n \"$PUSHED\" ]`" + ` tests it: an empty output would reach the command as ""`,
		}},
		{"guards a different variable", wf(producer + consumer(
			"          [ -n \"$DIGEST\" ] || exit 2\n          cosign sign \"$PUSHED\"\n")), 1, []string{
			where + ` is used before ` + "`[ -n \"$PUSHED\" ]`" + ` tests it: an empty output would reach the command as ""`,
		}},
		{"renamed id", wf(strings.Replace(producer, "id: push", "id: publish", 1) + consumer(
			"          [ -n \"$PUSHED\" ] || exit 2\n          cosign sign \"$PUSHED\"\n")), 1, []string{
			where + " names step id push, which no earlier step in the job declares",
		}},
		{"misspelled output", wf(strings.Replace(producer, "pushed=", "digest=", 1) + consumer(
			"          [ -n \"$PUSHED\" ] || exit 2\n          cosign sign \"$PUSHED\"\n")), 1, []string{
			where + " reads output pushed, which step push never writes to $GITHUB_OUTPUT",
		}},
		{"producer after the consumer", wf(consumer(
			"          [ -n \"$PUSHED\" ] || exit 2\n          cosign sign \"$PUSHED\"\n") + producer), 1, []string{
			where + " names step id push, which no earlier step in the job declares",
		}},
		// An env entry the step parse never reaches -- here at job level -- is
		// reported, not passed.
		{"outside a step", []byte("on: push\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    env:\n      PUSHED: ${{ steps.push.outputs.pushed }}\n    steps:" + producer), 0, []string{
			"t.yml: 1 env entries mapping a step output in the text, 0 inside a step",
		}},
		// Not a step output at all: nothing to judge.
		{"a secret, not a step output", wf(producer + "      - env:\n          KEY: ${{ secrets.KEY }}\n        run: cosign sign --key env://KEY x\n"), 0, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, n, err := envOutputProblems("t.yml", c.src)
			if err != nil {
				t.Fatal(err)
			}
			if n != c.sites {
				t.Errorf("judged %d sites, want %d", n, c.sites)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("problems = %q\nwant       %q", got, c.want)
			}
		})
	}
}
