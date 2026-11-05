package ciguard

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// QA 2026-11-02 #16: db-publish.yml's Build step read the dispatcher-written
// `seed` input by expression substitution into its script text --
// `--seed ${{ inputs.seed != '' && inputs.seed || steps.ref.outputs.ref }}` --
// in a job whose later steps hold COSIGN_PRIVATE_KEY. An expression is
// rendered before the shell parses the line, so whatever a dispatcher types
// is script, quotes and all; db-sign.yml had stated the project's rule the
// other way since D137 ("Both inputs reach the shell through env, never by
// expression substitution") and db-backfill.yml followed it, while nothing
// held db-publish.yml to it.
//
// So no run: block in any workflow may contain an expression that reads an
// input. The input goes through env: and the script reads "$NAME", which the
// shell treats as data. The guard is on the text shape, not on the risk of a
// particular input: a check that read the shape only where a secret was near
// would move with the secret.

// ghInputsWorkflow is the slice of a workflow this guard reads: env at every
// level and each step's run and env.
type ghInputsWorkflow struct {
	Env  map[string]string `yaml:"env"`
	Jobs map[string]struct {
		Env   map[string]string `yaml:"env"`
		Steps []ghStep          `yaml:"steps"`
	} `yaml:"jobs"`
}

// anyExpr matches one `${{ ... }}` expression, non-greedily so a `}` inside
// it (`format('{0}', ...)`) does not end the match early; readsInput says
// whether it touches the inputs context at all -- `inputs.<name>`, the older
// `github.event.inputs.<name>`, a bracket index `inputs['x']`, or the whole
// context in `toJSON(inputs)`. The word, not the dotted form: every honest
// spelling of a read names the context, and a guard that held only one
// spelling would be stepped around by the next (review of #231).
var (
	anyExpr    = regexp.MustCompile(`(?s)\$\{\{.*?\}\}`)
	readsInput = regexp.MustCompile(`\binputs\b`)
)

// inputExprs returns every expression in s that reads an input.
func inputExprs(s string) []string {
	var out []string
	for _, e := range anyExpr.FindAllString(s, -1) {
		if readsInput.MatchString(e) {
			out = append(out, e)
		}
	}
	return out
}

// inputsInRunProblems checks one workflow file's source and returns its
// problems and the number of input expressions it saw in env: blocks.
func inputsInRunProblems(file string, src []byte) ([]string, int, error) {
	var wf ghInputsWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", file, err)
	}
	var out []string
	inEnv := 0
	countEnv := func(env map[string]string) {
		for _, v := range env {
			inEnv += len(inputExprs(v))
		}
	}
	countEnv(wf.Env)
	inRun := 0
	for _, j := range slices.Sorted(maps.Keys(wf.Jobs)) {
		job := wf.Jobs[j]
		countEnv(job.Env)
		for _, s := range job.Steps {
			countEnv(s.Env)
			for _, e := range inputExprs(s.Run) {
				inRun++
				out = append(out, fmt.Sprintf("%s: job %s: run block substitutes `%s` into the script text: "+
					"an input is dispatcher-written and an expression is rendered before the shell parses the line, "+
					"so pass it through env: and read \"$NAME\" (db-sign.yml's rule)", file, j, e))
			}
		}
	}
	// The parse sees run: and env: blocks. An input expression anywhere else
	// -- an action's with: (actions/github-script evaluates `script:`), a
	// mis-indented step -- is missed, not passed, so the text must hold
	// exactly as many as the parse placed.
	if raw := len(inputExprs(string(src))); raw != inRun+inEnv {
		out = append(out, fmt.Sprintf("%s: %d expressions reading an input in the text, %d inside a step's run or an env: block", file, raw, inRun+inEnv))
	}
	return out, inEnv, nil
}

func TestNoWorkflowRunBlockSubstitutesAnInput(t *testing.T) {
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
		got, n, err := inputsInRunProblems(filepath.Base(f), src)
		if err != nil {
			t.Fatal(err)
		}
		perFile[filepath.Base(f)] = n
		for _, p := range got {
			t.Error(p)
		}
	}
	// The dispatchable workflows read their inputs through env: somewhere.
	// Without this, a pattern matching nothing would pass every workflow.
	for f, want := range map[string]int{
		"db-publish.yml":  3, // SEED, in the shape check and in Build; FORCE, in Publish
		"db-sign.yml":     6, // DIGEST and REPOSITORY, in three steps
		"db-backfill.yml": 2, // NVD_SINCE_DAYS, NVD_UNTIL_DAYS
	} {
		if perFile[f] != want {
			t.Errorf("%s: saw %d input expressions in env: blocks, want %d", f, perFile[f], want)
		}
	}
}

// The check against workflows it must reject, one defect per row, and the
// shapes it must accept. The first rejected row is main's own Build step as
// it stood before the fix (origin/main at 360f15d, db-publish.yml:141-155),
// so the guard is known to have been red on the defect it was written for.
func TestInputsInRunGuardRejects(t *testing.T) {
	wf := func(steps string) []byte {
		return []byte("on:\n  workflow_dispatch:\n    inputs:\n      seed:\n        type: string\n        default: \"\"\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:" + steps)
	}
	const mainBuildStep = `
      - id: ref
        run: echo "ref=$(./bin/assay db ref)" >> "$GITHUB_OUTPUT"
      - name: Build
        env:
          NVD_ENABLE: "1"
        run: |
          set -o pipefail
          # D110 recovery: dispatching with ` + "`seed`" + ` set to a ghcr digest (e.g.
          # the 08-30 snapshot that still carries Debian:11) reruns tonight's
          # build from that snapshot instead of an operator's machine -- selects the seed only, never --force.
          if ! ./bin/assay db build --seed ${{ inputs.seed != '' && inputs.seed || steps.ref.outputs.ref }} 2>&1 | tee /tmp/build.log; then
            if grep -q DENIED /tmp/build.log; then
              echo "::error::GITHUB_TOKEN cannot reach ${{ steps.ref.outputs.ref }}."
            fi
            exit 2
          fi
`
	const viaEnv = "\n      - env:\n          SEED: ${{ inputs.seed }}\n        run: ./bin/assay db build --seed \"$SEED\"\n"
	substitutes := func(expr string) string {
		return "t.yml: job publish: run block substitutes `" + expr + "` into the script text: " +
			"an input is dispatcher-written and an expression is rendered before the shell parses the line, " +
			"so pass it through env: and read \"$NAME\" (db-sign.yml's rule)"
	}
	cases := []struct {
		name  string
		src   []byte
		inEnv int
		want  []string
	}{
		{"well formed", wf(viaEnv), 1, nil},
		{"main's Build step before the fix", wf(mainBuildStep), 0, []string{
			substitutes("${{ inputs.seed != '' && inputs.seed || steps.ref.outputs.ref }}"),
		}},
		{"plain substitution", wf("\n      - run: ./bin/assay db build --seed ${{ inputs.seed }}\n"), 0, []string{
			substitutes("${{ inputs.seed }}"),
		}},
		// Quoting in the script is no defence: the expression is rendered
		// before the shell sees the quotes, so a seed holding `"` ends them.
		{"quoted substitution", wf("\n      - run: ./bin/assay db build --seed \"${{ inputs.seed }}\"\n"), 0, []string{
			substitutes("${{ inputs.seed }}"),
		}},
		{"github.event.inputs spelling", wf("\n      - run: echo ${{ github.event.inputs.seed }}\n"), 0, []string{
			substitutes("${{ github.event.inputs.seed }}"),
		}},
		// The spellings a first guard missed (review of #231): a function call
		// whose literal holds a brace, the whole context, a bracket index.
		{"inside format()", wf("\n      - run: echo ${{ format('{0}', inputs.since_days) }}\n"), 0, []string{
			substitutes("${{ format('{0}', inputs.since_days) }}"),
		}},
		{"toJSON of the whole context", wf("\n      - run: echo ${{ toJSON(inputs) }}\n"), 0, []string{
			substitutes("${{ toJSON(inputs) }}"),
		}},
		{"bracket index", wf("\n      - run: echo ${{ inputs['since_days'] }}\n"), 0, []string{
			substitutes("${{ inputs['since_days'] }}"),
		}},
		{"one via env, one substituted", wf(viaEnv + "      - run: echo ${{ inputs.seed }}\n"), 1, []string{
			substitutes("${{ inputs.seed }}"),
		}},
		// env: at job and workflow level reaches the shell as data too.
		{"job-level env", []byte("on: workflow_dispatch\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    env:\n      SEED: ${{ inputs.seed }}\n    steps:\n      - run: echo \"$SEED\"\n"), 1, nil},
		{"workflow-level env", []byte("on: workflow_dispatch\nenv:\n  SEED: ${{ inputs.seed }}\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"$SEED\"\n"), 1, nil},
		{"two inputs in one env value", wf("\n      - env:\n          WINDOW: ${{ inputs.since }}-${{ inputs.until }}\n        run: echo \"$WINDOW\"\n"), 2, nil},
		// An input expression the parse never places -- here an action's
		// with:, which actions/github-script evaluates as code -- is
		// reported, not passed.
		{"outside run and env", wf("\n      - uses: actions/github-script@v7\n        with:\n          script: console.log('${{ inputs.seed }}')\n"), 0, []string{
			"t.yml: 1 expressions reading an input in the text, 0 inside a step's run or an env: block",
		}},
		// Not an input. A step output in an exit is exit_fallback_test.go's
		// business; a secret in a run block is deliberately outside every
		// guard here -- GitHub masks it in the log and a token carries no
		// shell metacharacters, so the hazard this guard exists for (a
		// dispatcher-typed string rendered into the script) does not arise.
		{"a step output, not an input", wf("\n      - id: diff\n        run: echo \"exit_code=0\" >> \"$GITHUB_OUTPUT\"\n      - run: exit ${{ steps.diff.outputs.exit_code || 2 }}\n"), 0, nil},
		{"a secret, not an input", wf("\n      - run: echo \"${{ secrets.GITHUB_TOKEN }}\" | docker login --password-stdin\n"), 0, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, n, err := inputsInRunProblems("t.yml", c.src)
			if err != nil {
				t.Fatal(err)
			}
			if n != c.inEnv {
				t.Errorf("saw %d input expressions in env, want %d", n, c.inEnv)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("problems = %q\nwant       %q", got, c.want)
			}
		})
	}
}
