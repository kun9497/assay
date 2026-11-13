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

// downloadThenRun is the shape every install.sh one-liner takes instead:
// curl -f (an HTTP error is a non-zero status) writing the pinned script to
// assay-install.sh, then sh running THAT file -- behind && on the same line
// (the READMEs) or on the next line of a CI script, where the runner's
// shell stops at the failing download. Held as one pattern rather than as
// substrings, so a `;`, a run written before its download or a `|| true`
// cannot pass (PR #312 review).
var downloadThenRun = regexp.MustCompile(`curl -sSfL -o assay-install\.sh https://raw\.githubusercontent\.com/kun9497/assay/[0-9a-f]{40}/install\.sh(?: && |\n[ \t]*(?:- )?)(?:sudo )?sh \./assay-install\.sh -b /usr/local/bin`)

// TestInstallOneLiners_RunTheScriptOnlyAfterItDownloaded holds every install
// one-liner to the download-then-run shape: never piped into sh, and run
// through the file the download wrote, so a failed download is the
// command's failure.
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
		downloads := 0
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "/install.sh") && strings.Contains(line, "curl") {
				downloads++
			}
		}
		if shaped := len(downloadThenRun.FindAllString(text, -1)); downloads == 0 || shaped != downloads {
			t.Errorf("%s: %d line(s) download install.sh, %d in the download-then-run shape (curl -sSfL -o assay-install.sh <pinned url>, then sh ./assay-install.sh behind && or on the next line)", doc, downloads, shaped)
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
