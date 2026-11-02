package ciguard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Audit 2026-10-22 P4, re-verified 2026-11-02: a step that ends a job with
// `exit ${{ steps.<id>.outputs.<name> }}` fails OPEN when the output is empty.
// The expression renders to nothing, the shell runs a bare `exit`, and a bare
// `exit` returns the status of the last command -- 0 at the top of a step
// (bash -c 'true; exit' -> 0). scanner-diff.yml's verdict step had exactly
// that shape with no fallback: a renamed `id: diff`, a mistyped output name or
// an `if:` on the diff step would have turned every weekly run green, and the
// D138 alert job would then have closed the pinned failure issue on a
// differential that never judged. db-publish.yml's gate already carried
// `|| 2`; nothing held either one to it.
//
// So every such site must carry `|| <nonzero>`, and -- because the fallback
// only keeps the job red, it does not say why -- its <id> must name a step
// declared earlier in the same job that writes <name> to $GITHUB_OUTPUT. The
// fallback catches the rename; this second half makes the rename fail here,
// in a test, rather than as a mysterious red weekly run.

type ghWorkflow struct {
	Jobs map[string]struct {
		Steps []ghStep `yaml:"steps"`
	} `yaml:"jobs"`
}

type ghStep struct {
	ID  string `yaml:"id"`
	Run string `yaml:"run"`
}

// Any `exit ${{ ... }}`, whatever is inside: a site this cannot parse as a
// step output with a fallback is a problem, not something to skip.
var exitExpr = regexp.MustCompile(`exit\s+\$\{\{(.*?)\}\}`)

var stepOutputWithFallback = regexp.MustCompile(
	`^\s*steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*(?:\|\|\s*'?(-?[0-9]+)'?)?\s*$`)

// exitSiteProblems checks one workflow file's source and returns its problems
// and the number of `exit ${{ }}` sites it judged.
func exitSiteProblems(file string, src []byte) ([]string, int, error) {
	var wf ghWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", file, err)
	}
	var out []string
	sites := 0
	jobs := make([]string, 0, len(wf.Jobs))
	for j := range wf.Jobs {
		jobs = append(jobs, j)
	}
	slices.Sort(jobs)
	for _, j := range jobs {
		steps := wf.Jobs[j].Steps
		for i, s := range steps {
			for _, m := range exitExpr.FindAllStringSubmatch(s.Run, -1) {
				sites++
				where := fmt.Sprintf("%s: job %s: `%s`", file, j, strings.TrimSpace(m[0]))
				p := stepOutputWithFallback.FindStringSubmatch(m[1])
				if p == nil {
					out = append(out, where+" is not `steps.<id>.outputs.<name> || <nonzero>`")
					continue
				}
				id, name, fallback := p[1], p[2], p[3]
				if fallback == "" || strings.TrimLeft(strings.TrimPrefix(fallback, "-"), "0") == "" {
					out = append(out, where+" has no nonzero fallback: an empty output becomes a bare `exit`, which returns 0")
				} else if n, err := strconv.Atoi(fallback); err != nil || n%256 == 0 {
					// bash exits with its argument modulo 256, so `exit 256`
					// is `exit 0`: the fallback has to be nonzero AFTER that.
					out = append(out, where+" has a fallback the shell exits 0 on: `exit` takes its argument modulo 256")
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
	// The parse above sees only steps' run: blocks. A site anywhere else in
	// the file (a mis-indented step, a composite) would be missed, not passed,
	// so the raw text must hold no more sites than the parse judged.
	if raw := len(exitExpr.FindAll(src, -1)); raw != sites {
		out = append(out, fmt.Sprintf("%s: %d `exit ${{ }}` sites in the text, %d inside a step's run", file, raw, sites))
	}
	return out, sites, nil
}

func TestEveryWorkflowExitOnAStepOutputFailsClosed(t *testing.T) {
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
		got, n, err := exitSiteProblems(filepath.Base(f), src)
		if err != nil {
			t.Fatal(err)
		}
		perFile[filepath.Base(f)] = n
		for _, p := range got {
			t.Error(p)
		}
	}
	// The two sites this guard was written for. Without this, a pattern that
	// matched nothing would pass every workflow, including a broken one.
	for _, f := range []string{"scanner-diff.yml", "db-publish.yml"} {
		if perFile[f] != 1 {
			t.Errorf("%s: judged %d `exit ${{ steps... }}` sites, want 1", f, perFile[f])
		}
	}
}

// The check against workflows it must reject, one defect per row. Without
// this the guard is held only by the real workflows happening to be right.
func TestExitFallbackGuardRejects(t *testing.T) {
	const producer = `
      - id: diff
        run: |
          set +e
          ./bin/scandiff
          echo "exit_code=$?" >> "$GITHUB_OUTPUT"
`
	wf := func(steps string) []byte {
		return []byte("on: push\njobs:\n  diff:\n    runs-on: ubuntu-latest\n    steps:" + steps)
	}
	cases := []struct {
		name  string
		src   []byte
		sites int
		want  []string
	}{
		{"well formed", wf(producer + "      - run: exit ${{ steps.diff.outputs.exit_code || 2 }}\n"), 1, nil},
		{"fallback 256 exits 0", wf(producer + "      - run: exit ${{ steps.diff.outputs.exit_code || 256 }}\n"), 1, []string{
			"t.yml: job diff: `exit ${{ steps.diff.outputs.exit_code || 256 }}` has a fallback the shell exits 0 on: `exit` takes its argument modulo 256",
		}},
		{"no fallback", wf(producer + "      - run: exit ${{ steps.diff.outputs.exit_code }}\n"), 1, []string{
			"t.yml: job diff: `exit ${{ steps.diff.outputs.exit_code }}` has no nonzero fallback: an empty output becomes a bare `exit`, which returns 0",
		}},
		{"zero fallback", wf(producer + "      - run: exit ${{ steps.diff.outputs.exit_code || 0 }}\n"), 1, []string{
			"t.yml: job diff: `exit ${{ steps.diff.outputs.exit_code || 0 }}` has no nonzero fallback: an empty output becomes a bare `exit`, which returns 0",
		}},
		{"renamed id", wf(strings.Replace(producer, "id: diff", "id: differential", 1) + "      - run: exit ${{ steps.diff.outputs.exit_code || 2 }}\n"), 1, []string{
			"t.yml: job diff: `exit ${{ steps.diff.outputs.exit_code || 2 }}` names step id diff, which no earlier step in the job declares",
		}},
		{"misspelled output", wf(producer + "      - run: exit ${{ steps.diff.outputs.exitcode || 2 }}\n"), 1, []string{
			"t.yml: job diff: `exit ${{ steps.diff.outputs.exitcode || 2 }}` reads output exitcode, which step diff never writes to $GITHUB_OUTPUT",
		}},
		{"producer after the exit", wf("\n      - run: exit ${{ steps.diff.outputs.exit_code || 2 }}" + producer), 1, []string{
			"t.yml: job diff: `exit ${{ steps.diff.outputs.exit_code || 2 }}` names step id diff, which no earlier step in the job declares",
		}},
		{"not a step output", wf(producer + "      - run: exit ${{ env.RC }}\n"), 1, []string{
			"t.yml: job diff: `exit ${{ env.RC }}` is not `steps.<id>.outputs.<name> || <nonzero>`",
		}},
		// A site the step parse never reaches -- here an action's input, the
		// shape actions/github-script would take -- is reported, not passed.
		{"outside a step's run", wf(producer + "      - uses: actions/github-script@v7\n        with:\n          script: exit ${{ steps.diff.outputs.exit_code }}\n"), 0, []string{
			"t.yml: 1 `exit ${{ }}` sites in the text, 0 inside a step's run",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, n, err := exitSiteProblems("t.yml", c.src)
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
