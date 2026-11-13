package ciguard

import (
	"os"
	"regexp"
	"strings"
	"testing"
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
	leakedIntoJob = regexp.MustCompile(`(?m)^[ \t]*(?:- )?(?:t=\$\(mktemp\)|trap 'rm -f "\$t"' EXIT)[ \t]*$`)
)

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
		if m := leakedIntoJob.FindString(text); m != "" {
			t.Errorf("%s sets the installer's variable or trap in the calling shell, which GitLab shares with the job's own steps: %q", doc, strings.TrimSpace(m))
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
