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
// another way a step output reaches a shell is through `env:`, as
// `PUSHED: ${{ steps.push.outputs.pushed }}` does in db-publish.yml and
// db-backfill.yml. An empty output there is an empty variable, and the step
// runs on with it. For the signing step that meant cosign refusing "" three
// times and the step then reporting the artifact "pushed and UNSIGNED" --
// every db update refuses it until db-sign.yml is dispatched -- about a
// digest nobody had, when the real defect was a renamed `id: push` or a
// mistyped output name.
//
// So a step that maps a step output into env must open its run block by
// testing that variable non-empty AND stopping when it is not (`[ -n "$X" ]
// || { ...; exit <nonzero>; }`, `[ -n "$X" ] || exit <nonzero>`, or
// `: "${X:?...}"`), and, as for the exit sites, the output must come from a
// step declared earlier in the same job that writes it to $GITHUB_OUTPUT.
//
// Not covered: an output interpolated inline inside `run:` (`db push ${{
// steps.ref.outputs.ref }}`), which renders to nothing and fails in whatever
// way the command fails on a missing argument. The exit sites and the env
// mappings are the two shapes where an empty output changes a verdict
// silently; the inline shape is loud.

// envStepOutput matches an env value that is exactly one step output.
var envStepOutput = regexp.MustCompile(
	`^\s*\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*\}\}\s*$`)

// envKeyLine opens an env: mapping, as a step's first key (`- env:`) or not.
var envKeyLine = regexp.MustCompile(`^\s*(-\s+)?env:\s*$`)

// envStepOutputEntry is the raw-text shape of one such entry, quoted or not,
// for the count the parse is held to.
var envStepOutputEntry = regexp.MustCompile(
	`^\s*[A-Za-z_][A-Za-z0-9_]*:\s*['"]?\$\{\{\s*steps\.[A-Za-z0-9_-]+\.outputs\.[A-Za-z0-9_-]+\s*\}\}['"]?\s*$`)

// rawEnvOutputEntries counts, in the file's text, the entries inside any env:
// block whose value is a step output. Only env: blocks: a job's `outputs:` and
// an action's `with:` map step outputs too, and neither reaches a shell.
func rawEnvOutputEntries(src []byte) int {
	n, envCol := 0, -1
	for _, l := range strings.Split(string(src), "\n") {
		t := strings.TrimRight(l, " \t\r")
		if s := strings.TrimSpace(t); s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		col := len(t) - len(strings.TrimLeft(t, " "))
		if envCol >= 0 && col <= envCol {
			envCol = -1 // the block ended
		}
		if envCol < 0 {
			if envKeyLine.MatchString(t) {
				envCol = strings.Index(t, "env:")
			}
			continue
		}
		if envStepOutputEntry.MatchString(t) {
			n++
		}
	}
	return n
}

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

// nonEmptyGuard matches a first line that both tests name non-empty and
// stops the step when it is not. The test alone (`[ -n "$X" ]`, or one
// followed by `|| echo` or `|| exit 0`) is not a guard: the command after it
// still runs with "". The exit status is 1..255, because the shell takes it
// modulo 256 and `exit 256` is `exit 0` (the exit-fallback guard's rule).
func nonEmptyGuard(name string) *regexp.Regexp {
	q := regexp.QuoteMeta(name)
	const nonzero = `([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])`
	return regexp.MustCompile(
		`^(\[\s+-n\s+"\$\{?` + q + `\}?"\s+\]\s*\|\|\s*(\{.*\bexit\s+` + nonzero + `\s*;?\s*\}|exit\s+` + nonzero + `)\s*$` +
			`|:\s*"?\$\{` + q + `:\?)`)
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
					out = append(out, where+" is not guarded: the run block must open with `[ -n \"$"+v+
						"\" ] || { ...; exit <nonzero>; }` (or `: \"${"+v+":?...}\"`), else an empty output reaches the command as \"\"")
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
	// The parse sees steps' env: blocks. The same entry in an env: block
	// anywhere else (a job-level env, a mis-indented step) is missed, not
	// passed, so the text must hold no more such entries than the parse judged.
	if raw := rawEnvOutputEntries(src); raw != sites {
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

// The check against workflows it must reject, one defect per row, and the
// well-formed shapes it must accept.
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
	const unguarded = where + ` is not guarded: the run block must open with ` +
		"`[ -n \"$PUSHED\" ] || { ...; exit <nonzero>; }` (or `: \"${PUSHED:?...}\"`)" +
		`, else an empty output reaches the command as ""`
	const guarded = "          [ -n \"$PUSHED\" ] || { echo none; exit 2; }\n          cosign sign \"$PUSHED\"\n"
	cases := []struct {
		name  string
		src   []byte
		sites int
		want  []string
	}{
		{"well formed", wf(producer + consumer("          # a comment first is fine\n"+guarded)), 1, nil},
		{"plain exit", wf(producer + consumer("          [ -n \"$PUSHED\" ] || exit 1\n          cosign sign \"$PUSHED\"\n")), 1, nil},
		{"braced parameter form", wf(producer + consumer(
			"          : \"${PUSHED:?the Publish step recorded no digest}\"\n          cosign sign \"$PUSHED\"\n")), 1, nil},
		{"quoted env value", wf(producer + strings.Replace(consumer(guarded),
			"${{ steps.push.outputs.pushed }}", "\"${{ steps.push.outputs.pushed }}\"", 1)), 1, nil},
		{"no guard", wf(producer + consumer("          cosign sign \"$PUSHED\"\n")), 1, []string{unguarded}},
		{"guard after the use", wf(producer + consumer(
			"          cosign sign \"$PUSHED\"\n          [ -n \"$PUSHED\" ] || exit 2\n")), 1, []string{unguarded}},
		{"guards a different variable", wf(producer + consumer(
			"          [ -n \"$DIGEST\" ] || exit 2\n          cosign sign \"$PUSHED\"\n")), 1, []string{unguarded}},
		// A test that does not stop the step is not a guard.
		{"test with no abort", wf(producer + consumer(
			"          [ -n \"$PUSHED\" ]\n          cosign sign \"$PUSHED\"\n")), 1, []string{unguarded}},
		{"test that only warns", wf(producer + consumer(
			"          [ -n \"$PUSHED\" ] || echo \"::warning::empty\"\n          cosign sign \"$PUSHED\"\n")), 1, []string{unguarded}},
		{"test that exits 0", wf(producer + consumer(
			"          [ -n \"$PUSHED\" ] || exit 0\n          cosign sign \"$PUSHED\"\n")), 1, []string{unguarded}},
		{"test that exits 256", wf(producer + consumer(
			"          [ -n \"$PUSHED\" ] || { echo none; exit 256; }\n          cosign sign \"$PUSHED\"\n")), 1, []string{unguarded}},
		{"renamed id", wf(strings.Replace(producer, "id: push", "id: publish", 1) + consumer(guarded)), 1, []string{
			where + " names step id push, which no earlier step in the job declares",
		}},
		{"misspelled output", wf(strings.Replace(producer, "pushed=", "digest=", 1) + consumer(guarded)), 1, []string{
			where + " reads output pushed, which step push never writes to $GITHUB_OUTPUT",
		}},
		{"producer after the consumer", wf(consumer(guarded) + producer), 1, []string{
			where + " names step id push, which no earlier step in the job declares",
		}},
		// An env entry the step parse never reaches -- here at job level -- is
		// reported, not passed.
		{"outside a step", []byte("on: push\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    env:\n      PUSHED: ${{ steps.push.outputs.pushed }}\n    steps:" + producer), 0, []string{
			"t.yml: 1 env entries mapping a step output in the text, 0 inside a step",
		}},
		// A step output mapped somewhere other than env: reaches no shell and
		// is not counted: a job's outputs: and an action's with:.
		{"job outputs and action inputs", []byte("on: push\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    outputs:\n      digest: ${{ steps.push.outputs.pushed }}\n    steps:" + producer +
			"      - uses: actions/upload-artifact@v4\n        with:\n          name: ${{ steps.push.outputs.pushed }}\n          path: ./x\n"), 0, nil},
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
