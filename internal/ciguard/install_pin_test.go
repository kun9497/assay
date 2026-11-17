package ciguard

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// installPinDocs are the documents whose install one-liners the release job
// re-pins to the tagged commit (.github/workflows/release.yml). A reader
// copies the one-liner from any of them, so they must agree with each other
// at every commit, not only at the one a tag happens to produce.
var installPinDocs = []string{
	"README.md",
	"README.ko.md",
	"docs/ci/github-actions.yml",
	"docs/ci/gitlab-ci.yml",
}

// installRef captures the ref part of an install one-liner: the release job's
// sed accepts anything without a slash there ([^/]+), so this is what a branch
// name or a tag would also match -- the assertion below is what refuses them.
var installRef = regexp.MustCompile(`raw\.githubusercontent\.com/kun9497/assay/([^/]+)/install\.(sh|ps1)`)

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// pipedIntoSh is the one-liner shape the Linux QA of v0.18.1 (2026-11-13)
// found returning 0 on a failed download: `curl ... | sh`'s exit status is
// sh's, and sh reading nothing exits clean, so a reader's shell saw success
// with nothing installed. The documents run the script only after it
// downloaded (`curl -o ... && sh ...`).
var pipedIntoSh = regexp.MustCompile(`install\.(sh|ps1)[^\n]*\|\s*(sudo(\s+-\S+)*\s+)?(sh|bash)\b`)

// The one shape every install.sh one-liner takes instead, READMEs and CI
// examples alike: one `sh -c` line in which curl -f (an HTTP error is a
// non-zero status) writes the pinned script to a file mktemp made, sh runs
// THAT file, the file is removed and the line exits with the install's
// status. Held as one pattern rather than as substrings, so a `;`, a run
// written before its download or a `|| true` cannot pass (PR #312 review).
// A fixed name in the working directory is refused: the first revision wrote
// `./assay-install.sh` and overwrote a file of that name (main QA of 672fe7a,
// 2026-11-13). A variable or EXIT trap left in the calling shell is refused
// too: GitLab runs before_script and script in one shell, and the four-line
// form's `trap 'rm -f "$t"' EXIT` deleted a report.txt a later job step had
// put in t (main QA of ef0bc1a, 2026-11-13).
var (
	pinnedScript = `https://raw\.githubusercontent\.com/kun9497/assay/[0-9a-f]{40}/install\.sh`
	// Anchored to the line, so nothing may follow the shape: a trailing
	// `|| true` or `; exit 0` would hand the caller a success again (PR
	// #315 review).
	oneLinerShape = regexp.MustCompile(`(?m)^[ \t]*(?:- )?sh -c 't=\$\(mktemp\) && curl -sSfL -o "\$t" ` + pinnedScript + ` && (?:sudo )?sh "\$t" -b /usr/local/bin; s=\$\?; rm -f "\$t"; exit \$s'$`)
	fixedName     = regexp.MustCompile(`-o +\.?/?assay-install\.sh`)
)

// leakedInInstallJob is what the guard refuses in a document: the first
// variable or EXIT trap left in a job that installs, "" when there is none.
// TestInstallOneLiners_RunTheScriptOnlyAfterItDownloaded holds the shipped
// documents to it, and TestInstallOneLiners_LeakGuardReadsTheInstallJobOnly
// holds it to composed ones -- the shipped documents are clean, so only the
// composed ones can show the job scoping and the EXIT-only match at work.
func leakedInInstallJob(text string) string {
	for _, job := range installJobs(text) {
		if line := leakedIntoJob.FindString(job); line != "" {
			return line
		}
	}
	return ""
}

// A GitHub Actions run step gets its own shell. Inspect the decoded script
// of each step containing the install one-liner, with fresh state per step.
func leakedInGitHubInstallRun(t *testing.T, text string) string {
	t.Helper()
	var workflow ghWorkflow
	if err := yaml.Unmarshal([]byte(text), &workflow); err != nil {
		t.Fatalf("parse GitHub Actions install example: %v", err)
	}
	found := false
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if !containsInstallDownload(step.Run) {
				continue
			}
			found = true
			if line := firstShellLeak(step.Run); line != "" {
				return line
			}
		}
	}
	if !found {
		t.Error("GitHub Actions install example has no run step containing the install one-liner")
	}
	return ""
}

func containsInstallDownload(script string) bool {
	for _, line := range strings.Split(script, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.Contains(line, "/install.sh") && strings.Contains(line, "curl") {
			return true
		}
	}
	return false
}

// installJobs is the part of a document the install lines are steps of:
// for each line that downloads install.sh, the block holding it -- the
// top-level GitLab job whose before_script and script share one shell, or
// the fenced example in a README.
// What another block sets is that block's own (main QA of 67e2cf6,
// 2026-11-13: a TERM trap in an independent GitLab job of the example was
// refused as the installer's leftover); every block that installs is read
// (PR #325 review: only the first had been, so a second installing job's
// EXIT trap passed). A document with no install line is returned whole, so
// the leak check still reads it.
func installJobs(text string) []string {
	lines := strings.Split(text, "\n")
	indent := func(line string) int { return len(line) - len(strings.TrimLeft(line, " \t")) }
	// A boundary starts a block: a fence line, or a line outside a fence
	// that is not indented and not a comment.
	boundary := make([]bool, len(lines))
	inFence := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "```") {
			boundary[i] = true
			inFence = !inFence
			continue
		}
		boundary[i] = !inFence && line != "" && indent(line) == 0 && line[0] != '#'
	}
	blockOf := func(i int) (int, int) {
		start, end := 0, len(lines)
		for k := i; k >= 0; k-- {
			if boundary[k] {
				start = k
				break
			}
		}
		for k := i + 1; k < len(lines); k++ {
			if boundary[k] {
				end = k
				break
			}
		}
		return start, end
	}
	var blocks []string
	seen := map[[2]int]bool{}
	for i, line := range lines {
		if !strings.Contains(line, "/install.sh") || !strings.Contains(line, "curl") {
			continue
		}
		start, end := blockOf(i)
		if !seen[[2]int{start, end}] {
			seen[[2]int{start, end}] = true
			blocks = append(blocks, strings.Join(lines[start:end], "\n"))
		}
	}
	if blocks == nil {
		return []string{text}
	}
	return blocks
}

// TestInstallOneLiners_LeakGuardCatchesTheFourLineForm holds the guard that
// refuses a variable or trap left in the calling shell against the four-line
// form ef0bc1a's docs/ci/gitlab-ci.yml carried, in the spellings a reader
// would write: without this fixture the guard was held by nothing (PR #319
// review -- no document carries the shape, so a regex that matched nothing
// stayed green).
func TestInstallOneLiners_LeakGuardCatchesTheFourLineForm(t *testing.T) {
	for _, line := range []string{
		"    - t=$(mktemp)",
		"    - trap 'rm -f \"$t\"' EXIT",
		"          t=$(mktemp)",
		"          trap 'rm -f \"$t\"' EXIT",
		"    -   t=\"$(mktemp)\"",
		"    - export t=$(mktemp)",
		"    - f=$(mktemp -d)",
		"    - t=$(mktemp) # the installer's file",
		"    - trap \"rm -f $t\" EXIT",
		"    - trap 'rm -f \"$t\"' EXIT TERM",
		"    - trap 'rm -f \"$t\"' INT TERM EXIT",
		"    - trap 'rm -f \"$t\"' 0",
		// PR #325 review: sh reads signal names in any case, and a
		// double-quoted handler may escape its inner quotes.
		"    - trap 'rm -f \"$t\"' exit",
		"    - trap \"rm -f \\\"$t\\\"\" EXIT",
		"    - trap cleanup EXIT",
		// A quoted signal name is the signal (main QA of f554fb2).
		"    - trap 'echo cleanup' " + `"EXIT"`,
		"    - trap 'echo cleanup' 'EXIT'",
		"    - trap 'echo cleanup' 'TERM' " + `"EXIT"`,
		"    - trap 'echo cleanup' \"0\"",
		// PR #327 review: the POSIX option separator, a YAML-quoted item,
		// and a trap after another command on the same line.
		"    - trap -- 'rm -f \"$t\"' EXIT",
		"    - trap -- 'rm -f \"$t\"' \"EXIT\"",
		"    - \"trap 'rm -f \\\"$t\\\"' EXIT\"",
		"    - set -e; trap 'rm -f \"$t\"' EXIT",
		"    - true && trap 'rm -f \"$t\"' EXIT",
		// Second review of PR #327: the mktemp half takes the same prefix,
		// and a trap in a group, a compound body or after `&` is a trap.
		"    - set -e; t=$(mktemp)",
		"    - true && t=\"$(mktemp)\"",
		"    - \"t=$(mktemp)\"",
		"    - if true; then trap 'rm -f \"$t\"' EXIT; fi",
		"    - { trap 'rm -f \"$t\"' EXIT; }",
		"    - true & trap 'rm -f \"$t\"' EXIT",
	} {
		if !leakedIntoJob.MatchString(line + "\n") {
			t.Errorf("leakedIntoJob does not catch %q", line)
		}
	}
	for _, line := range []string{
		"    - sh -c 't=$(mktemp) && curl -sSfL -o \"$t\" https://raw.githubusercontent.com/kun9497/assay/0123456789abcdef0123456789abcdef01234567/install.sh && sh \"$t\" -b /usr/local/bin; s=$?; rm -f \"$t\"; exit $s'",
		"    - apk add --no-cache curl openssl",
		"    # the temporary file, the download, the run and the clean-up",
		// A job's own signal handling, not the installer's leftover (main
		// QA of 67e2cf6, 2026-11-13).
		"    - trap 'echo stopping' TERM",
		"    - trap 'cleanup' INT TERM",
		"    - trap - EXIT",
		"    - trap 'echo' 10",
		"    - trap 'echo stopping' " + `"TERM"`,
		"    - trap 'echo' '10'",
		"    - trap -- 'echo stopping' TERM",
		"    - set -e; trap 'echo stopping' TERM",
		"    - echo 'no trap here; exit 0'",
		// A trap inside a quoted string -- a child shell's, or text -- is
		// not the job shell's (second review of PR #327).
		"    - sh -c 'd=$(mktemp -d); trap \"rm -rf $d\" EXIT; make'",
		"    - echo \"a; trap 'x' EXIT\"",
	} {
		if leakedIntoJob.MatchString(line + "\n") {
			t.Errorf("leakedIntoJob wrongly catches %q", line)
		}
	}
}

// TestInstallOneLiners_RunTheScriptOnlyAfterItDownloaded holds every install
// one-liner to the download-then-run shape: never piped into sh, run through
// the temporary file the download wrote and removed afterwards, so a failed
// download is the command's failure and the working directory is untouched.
func TestInstallOneLiners_RunTheScriptOnlyAfterItDownloaded(t *testing.T) {
	for _, doc := range installPinDocs {
		b, err := os.ReadFile(repoRoot + "/" + doc)
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		text := strings.ReplaceAll(string(b), "\r\n", "\n")
		if m := pipedIntoSh.FindString(text); m != "" {
			t.Errorf("%s pipes the installer into sh, which returns 0 on a failed download: %q", doc, m)
		}
		if m := fixedName.FindString(text); m != "" {
			t.Errorf("%s downloads the installer to a fixed name in the working directory, which overwrites a file of that name: %q", doc, m)
		}
		var leak string
		if doc == "docs/ci/github-actions.yml" {
			leak = leakedInGitHubInstallRun(t, text)
		} else {
			leak = leakedInInstallJob(text)
		}
		if leak != "" {
			t.Errorf("%s sets the installer's variable or trap in the calling shell: %q", doc, strings.TrimSpace(leak))
		}
		downloads := 0
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "/install.sh") && strings.Contains(line, "curl") {
				downloads++
			}
		}
		shaped := len(oneLinerShape.FindAllString(text, -1))
		if downloads == 0 || shaped != downloads {
			t.Errorf("%s: %d line(s) download install.sh, %d in the one-line download-to-mktemp-then-run-then-remove shape", doc, downloads, shaped)
		}
	}
}

// TestInstallOneLiners_PinOneCommit holds the four documents a reader copies
// an install one-liner from to the invariant the release job's sed only
// restores at tag time: every ref is a 40-hex commit SHA (a branch or tag can
// be moved and raw.githubusercontent.com re-serves the moved one) and all of
// them name the same commit. Until QA 2026-11-04 the release job's loop
// listed only the two READMEs, so four releases' pin commits left docs/ci on
// `main` with nothing going red; this is the test that would have.
func TestInstallOneLiners_PinOneCommit(t *testing.T) {
	refs := map[string][]string{} // ref -> "doc:line" occurrences
	total := 0
	for _, doc := range installPinDocs {
		b, err := os.ReadFile(repoRoot + "/" + doc)
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		found := 0
		for _, m := range installRef.FindAllStringSubmatch(string(b), -1) {
			ref := m[1]
			if !fullSHA.MatchString(ref) {
				t.Errorf("%s: install.%s is fetched from %q, want a 40-hex commit SHA, never a branch or tag", doc, m[2], ref)
			}
			refs[ref] = append(refs[ref], doc)
			found++
		}
		if found == 0 {
			t.Errorf("%s: no install one-liner found; the release job expects one to re-pin", doc)
		}
		total += found
	}
	if len(refs) > 1 {
		t.Errorf("the %d install one-liners pin %d different refs, want one: %v", total, len(refs), refs)
	}
}

// TestInstallOneLiners_LeakGuardReadsTheInstallJobOnly holds installJob and
// the guard together over document shapes: the current GitLab example with
// an independent job added after it -- one trapping TERM, one trapping EXIT,
// one making its own temporary file -- or before it passes, since what that
// job sets is its own (main QA of 67e2cf6, 2026-11-13: the TERM one was
// refused); the four-line install form ef0bc1a's example carried is still
// refused inside the install job, and a document with no install line is
// read whole.
func TestInstallOneLiners_LeakGuardReadsTheInstallJobOnly(t *testing.T) {
	b, err := os.ReadFile(repoRoot + "/docs/ci/gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	current := strings.ReplaceAll(string(b), "\r\n", "\n")
	if !strings.Contains(current, "assay_scan:\n") {
		t.Fatalf("docs/ci/gitlab-ci.yml no longer holds the assay_scan job this test composes with")
	}
	independent := "independent_report:\n  script:\n    - trap 'rm -f report.tmp' EXIT\n    - t=$(mktemp)\n    - trap 'echo stopping' TERM\n    - echo report > \"$t\"\n"
	for name, doc := range map[string]string{
		"TERM trap after":  current + "\nindependent_report:\n  script:\n    - trap 'echo stopping' TERM\n    - echo report\n",
		"EXIT trap after":  current + "\n" + independent,
		"EXIT trap before": independent + "\n" + current,
	} {
		if m := leakedInInstallJob(doc); m != "" {
			t.Errorf("%s: the guard refused %q outside the install job", name, strings.TrimSpace(m))
		}
	}
	fourLine := strings.Replace(current,
		"    - sh -c 't=$(mktemp) && curl -sSfL -o \"$t\" ",
		"    - t=$(mktemp)\n    - trap 'rm -f \"$t\"' EXIT\n    - curl -sSfL -o \"$t\" ", 1)
	if fourLine == current {
		t.Fatalf("could not compose the four-line form from the current example")
	}
	if m := leakedInInstallJob(fourLine); m == "" {
		t.Errorf("the four-line form inside the install job is not refused")
	}
	if m := leakedInInstallJob(fourLine + "\n" + independent); m == "" {
		t.Errorf("the four-line form inside the install job is not refused when another job follows")
	}
	if got := installJobs("a: 1\nb:\n  - x\n"); len(got) != 1 || got[0] != "a: 1\nb:\n  - x\n" {
		t.Errorf("a document with no install line is not read whole: %q", got)
	}
}

// PR #325 review: every block that installs is read, a README's fenced
// example is the block around its one-liner. Each case is the shipped document
// with one addition; the guard refuses a leftover inside an install block
// and lets one outside pass.
func TestInstallOneLiners_LeakGuardBlocksPerDocumentShape(t *testing.T) {
	read := func(doc string) string {
		b, err := os.ReadFile(repoRoot + "/" + doc)
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	gitlab, readme := read("docs/ci/gitlab-ci.yml"), read("README.md")
	oneLiner := ""
	for _, line := range strings.Split(gitlab, "\n") {
		if strings.Contains(line, "/install.sh") {
			oneLiner = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
		}
	}
	readmeLine := ""
	for _, line := range strings.Split(readme, "\n") {
		if strings.Contains(line, "/install.sh") && strings.Contains(line, "curl") {
			readmeLine = line
			break
		}
	}
	if oneLiner == "" || readmeLine == "" {
		t.Fatal("the shipped documents no longer carry the install line this test composes with")
	}
	for _, tc := range []struct {
		name, doc string
		refused   bool
	}{
		{"second GitLab install job with an EXIT trap", gitlab + "\nsecond_scan:\n  before_script:\n    - trap 'rm -f \"$t\"' EXIT\n    - " + oneLiner + "\n  script:\n    - assay scan x > report.txt\n", true},
		{"GitLab install job with a double-quoted EXIT", strings.Replace(gitlab, "    - "+oneLiner, "    - trap 'echo cleanup' \"EXIT\"\n    - "+oneLiner, 1), true},
		{"GitLab install job with a single-quoted EXIT", strings.Replace(gitlab, "    - "+oneLiner, "    - trap 'echo cleanup' 'EXIT'\n    - "+oneLiner, 1), true},
		{"GitLab install job with a quoted TERM", strings.Replace(gitlab, "    - "+oneLiner, "    - trap 'echo stopping' \"TERM\"\n    - "+oneLiner, 1), false},
		{"second GitLab install job with a mktemp variable", gitlab + "\nsecond_scan:\n  before_script:\n    - t=$(mktemp)\n    - " + oneLiner + "\n", true},
		{"README: a trap beside the one-liner in its fence", strings.Replace(readme, readmeLine, readmeLine+"\ntrap 'rm -f \"$t\"' EXIT", 1), true},
		{"README: a mktemp variable opening the fence", strings.Replace(readme, readmeLine, "t=$(mktemp)\n"+readmeLine, 1), true},
		{"README: a trap in another fence", readme + "\n```sh\ntrap 'rm -f work.tmp' EXIT\n```\n", false},
	} {
		got := leakedInInstallJob(tc.doc)
		if (got != "") != tc.refused {
			t.Errorf("%s: guard found %q, want refused = %v", tc.name, strings.TrimSpace(got), tc.refused)
		}
	}
}

func TestInstallOneLiners_GitHubRunShellScope(t *testing.T) {
	const install = "curl -fsSL https://example.test/install.sh -o install"
	const trap = "trap 'echo cleanup' EXIT"
	const assign = "cleanup='trap echo EXIT'"
	const evaluate = "eval \"$cleanup\""
	step := func(script string) string {
		return "      - run: |\n          " + strings.ReplaceAll(script, "\n", "\n          ") + "\n"
	}
	job := "    runs-on: ubuntu-latest\n    steps:\n"
	for _, tc := range []struct {
		name, steps string
		wantLeak    bool
	}{
		{"another job", step(install) + "  other:\n" + job + step(trap), false},
		{"other run before", step(trap) + step(install), false},
		{"other run after", step(install) + step(trap), false},
		{"local variable from other run", step(assign) + step(install+"\n"+evaluate), false},
		{"trap in install run", step(trap + "\n" + install), true},
		{"trap in second install run", step(install) + step(install+"\n"+trap), true},
		{"variable in install run", step(install + "\n" + assign + "\n" + evaluate), true},
		{"folded install run", "      - run: >-\n          " + install + ";\n          " + trap + "\n", true},
		{"continued signal", step(install + "\ntrap 'echo cleanup' \\\n  EXIT"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workflow := "jobs:\n  install:\n" + job + tc.steps
			if got := leakedInGitHubInstallRun(t, workflow); (got != "") != tc.wantLeak {
				t.Errorf("found %q, want leak = %v", got, tc.wantLeak)
			}
		})
	}
}
