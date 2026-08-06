package requirements

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write puts content in a temp requirements.txt and returns its path. Written
// byte-for-byte so a test can exercise continuations and BOMs.
func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// classify's whole contract, as a table. The cases come from pip's own source
// and from the review that found two false-negative paths in an earlier draft
// of this rule.
func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		name    string
		line    string
		kind    lineKind
		pkgName string
		version string
		why     string
	}{
		// --- pinned: the only shapes that may become a package -------------
		{"exact", "Django==3.2.12", kindPinned, "Django", "3.2.12",
			"a single == clause names one release"},
		{"exact two-component", "Django==3.2", kindPinned, "Django", "3.2",
			"PEP 440 zero-pads the release segment, so 3.2 IS 3.2.0 — one release, not a range"},
		{"arbitrary equality", "foo===1.0-legacy", kindPinned, "foo", "1.0-legacy",
			"=== is byte equality; the version may not parse as PEP 440, and that must reach the comparer as a loud skip"},
		{"spaces around the operator", "Django == 3.2.12", kindPinned, "Django", "3.2.12",
			"pip tolerates whitespace inside a specifier"},
		{"extras are not part of the name", "Django[bcrypt]==3.2.12", kindPinned, "Django", "3.2.12",
			"extras select optional dependencies; the distribution is still Django"},
		{"marker is dropped, not evaluated", `Django==3.2.12 ; python_version < "3.8"`, kindPinned, "Django", "3.2.12",
			"D38: evaluating a marker would need the deployment environment, not this one"},
		{"hash option is stripped", "Django==3.2.12 --hash=sha256:abc", kindPinned, "Django", "3.2.12",
			"break_args_options splits the requirement from its options"},

		// --- the wildcard, which is a range wearing an == -------------------
		{"wildcard is not a pin", "Django==3.2.*", kindUnusable, "", "",
			"==3.2.* admits 3.2.1 and 3.2.0.post1; treating it as 3.2 would report a fixed release as vulnerable"},
		// The case that broke the first draft of the rule. A rule phrased as
		// "exactly one == clause, all others !=" admits this, because the
		// wildcard exclusion was written only into the single-clause branch.
		{"wildcard inside a multi-clause set", "foo==1.4.*,!=1.4.1", kindUnusable, "", "",
			"the hole a review found: one == clause, all others !=, and still a range"},
		{"multi-clause is refused even when it does pin", "Django==3.2,!=3.2.1", kindUnusable, "", "",
			"this really does name 3.2, and is refused anyway so that no multi-clause case exists to get wrong"},

		// --- ordinary constraints -------------------------------------------
		{"lower bound", "Django>=3.2", kindUnusable, "", "", "the shape D26 refused to guess at"},
		{"compatible release", "Django~=3.2.1", kindUnusable, "", "", "~=X.Y.Z is >=X.Y.Z,==X.Y.*"},
		{"range", "Django>=3.2,<4", kindUnusable, "", "", ""},
		{"exclusion only", "Django!=3.2", kindUnusable, "", "", ""},
		{"bare name", "Django", kindUnusable, "", "", "no version at all"},

		// --- not requirements at all ----------------------------------------
		{"index url", "--index-url https://pypi.org/simple", kindIgnorable, "", "",
			"configures pip; counting it as a component would inflate 'not evaluated' with non-packages"},
		{"find links", "--find-links ./wheels", kindIgnorable, "", "", ""},
		{"include", "-r base.txt", kindUnusable, "", "",
			"a file whose every line is -r would otherwise catalog nothing and report a clean scan"},
		{"include long form", "--requirement base.txt", kindUnusable, "", "", ""},
		{"constraint file", "-c constraints.txt", kindUnusable, "", "", ""},
		{"editable", "-e .", kindUnusable, "", "", ""},
		{"editable vcs", "-e git+https://example.com/x.git#egg=x", kindUnusable, "", "", ""},

		// --- shapes that carry a version this parser will not read -----------
		{"direct reference", "Django @ https://example.com/Django-3.2.12-py3-none-any.whl", kindUnusable, "", "",
			"the version is there, and reading it means stripping fragments and query strings first"},
		{"vcs url", "git+https://example.com/x.git@v1.2.3", kindUnusable, "", "", ""},
		{"local path", "./vendor/pkg", kindUnusable, "", "", ""},
		{"wheel filename", "Django-3.2.12-py3-none-any.whl", kindUnusable, "", "", ""},

		// --- pip expands these; this parser must not -------------------------
		{"environment variable", "Django==${DJANGO_VERSION}", kindUnusable, "", "",
			"expanding from this process's environment would invent a version the file never stated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, d := classify(tc.line)
			if kind != tc.kind {
				t.Fatalf("classify(%q) kind = %v, want %v (%s)", tc.line, kind, tc.kind, tc.why)
			}
			if kind != kindPinned {
				return
			}
			if d.name != tc.pkgName || d.version != tc.version {
				t.Errorf("classify(%q) = %s@%s, want %s@%s", tc.line, d.name, d.version, tc.pkgName, tc.version)
			}
		})
	}
}

// pip's comment rule, which is not "cut at the first #". Getting this wrong
// mangles URL fragments, and a parser that read versions off URLs would then
// read the wrong one.
func TestLogicalLines_CommentsFollowPip(t *testing.T) {
	p := write(t, strings.Join([]string{
		"# a whole-line comment",
		"Django==3.2.12  # trailing comment",
		"foo==1.0#notacomment",
		"-e git+https://example.com/x.git#egg=x",
		"",
		"   ",
	}, "\n"))
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := logicalLines(f)
	want := []string{
		"Django==3.2.12",
		// No whitespace before '#', so it is part of the requirement, not a
		// comment. pip agrees; strings.Index does not.
		"foo==1.0#notacomment",
		"-e git+https://example.com/x.git#egg=x",
	}
	if len(got) != len(want) {
		t.Fatalf("logicalLines = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// Continuations are joined BEFORE comments are stripped, which is pip's order.
// Reversing it lets a trailing comment swallow the backslash and glue two
// requirements into one.
func TestLogicalLines_ContinuationBeforeComment(t *testing.T) {
	p := write(t, "Django==\\\n3.2.12\nflask==2.0.0\n")
	f, _ := os.Open(p)
	defer f.Close()
	got := logicalLines(f)
	if len(got) != 2 || got[0] != "Django==3.2.12" {
		t.Errorf("logicalLines = %q, want the continued line joined into one requirement", got)
	}
}

// A UTF-8 BOM belongs to the file, not to the first requirement. Written from
// its code point rather than typed, for the reason the production code says.
func TestLogicalLines_BOMIsNotPartOfTheName(t *testing.T) {
	p := write(t, string(rune(0xFEFF))+"Django==3.2.12\n")
	f, _ := os.Open(p)
	defer f.Close()
	got := logicalLines(f)
	if len(got) != 1 || got[0] != "Django==3.2.12" {
		t.Errorf("logicalLines = %q, want the BOM stripped from the first line", got)
	}
}

// The counts the report derives its "not evaluated" figure from. Components
// counts requirements; options are not requirements and must not inflate it.
func TestParse_Counts(t *testing.T) {
	p := write(t, strings.Join([]string{
		"--index-url https://pypi.org/simple",
		"# comment",
		"Django==3.2.12",
		"flask>=2.0",
		"-r base.txt",
		"requests",
	}, "\n"))
	target, stats, unusable, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 || target.Packages[0].Name != "Django" {
		t.Errorf("Packages = %+v, want only the pinned Django", target.Packages)
	}
	if target.Packages[0].Ecosystem != "PyPI" {
		t.Errorf("Ecosystem = %q, want PyPI", target.Packages[0].Ecosystem)
	}
	if stats.Components != 4 {
		t.Errorf("Components = %d, want 4 (three unusable requirements plus the pinned one; the option is not a component)", stats.Components)
	}
	if stats.Cataloged != 1 {
		t.Errorf("Cataloged = %d, want 1", stats.Cataloged)
	}
	if stats.SkippedNoVersion != 3 {
		t.Errorf("SkippedNoVersion = %d, want 3", stats.SkippedNoVersion)
	}
	// Named, not just counted: pinning them is the action being asked for, and
	// "3 packages with no version" does not say which three.
	if len(unusable) != 3 {
		t.Fatalf("unusable = %+v, want 3 entries", unusable)
	}
	for _, u := range unusable {
		if u.Line == "" || u.Reason == "" {
			t.Errorf("unusable entry %+v has an empty line or reason", u)
		}
	}
	if !strings.Contains(unusable[0].Line, "flask") {
		t.Errorf("unusable[0] = %+v, want the flask constraint first, in file order", unusable[0])
	}
}

// A file that is nothing but includes catalogs no packages. It must not report
// as a clean, complete scan — that is the shape a review found reported as
// clean, and it is 1.8% of the sampled corpus.
func TestParse_IncludeOnlyFileIsNotClean(t *testing.T) {
	p := write(t, "-r requirements/base.txt\n-r requirements/prod.txt\n")
	_, stats, unusable, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Cataloged != 0 {
		t.Fatalf("Cataloged = %d, want 0", stats.Cataloged)
	}
	if stats.Components != 2 || stats.SkippedNoVersion != 2 {
		t.Errorf("Components=%d SkippedNoVersion=%d, want 2 and 2: an include is a component this scan did not evaluate",
			stats.Components, stats.SkippedNoVersion)
	}
	if len(unusable) != 2 {
		t.Errorf("unusable = %d entries, want both includes named", len(unusable))
	}
}

func TestParse_MissingFile(t *testing.T) {
	_, _, _, err := Parse(filepath.Join(t.TempDir(), "nope.txt"))
	if err == nil {
		t.Fatal("Parse of a missing file returned no error")
	}
	// The basename, not the whole path: the error is rendered next to a scan
	// that already printed the directory, and the file it names is the useful
	// half.
	if !strings.Contains(err.Error(), "nope.txt") {
		t.Errorf("err = %v, want it to name the file it could not read", err)
	}
}
