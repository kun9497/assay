package ciguard

import (
	"strings"
	"testing"
	"time"
)

// leakRows is the rule's contract: one row per branch of it and per
// historical false positive, not one per spelling. The "hidden" group pins
// what the guard does not claim to catch (leakGuard's comment), so that
// claim cannot drift into a promise.
var leakRows = []struct {
	group, name, script string
	refused             bool
}{
	// 1. eval, wherever it stands and whatever it would run.
	{"eval", "literal", `eval "trap 'echo x' EXIT"`, true},
	{"eval", "stored", `cleanup='trap "echo cleanup" EXIT'; eval "$cleanup"`, true},
	{"eval", "after-command", `command eval 'trap : EXIT'`, true},
	{"eval", "harmless", `c='echo ok'; eval "$c"`, true},
	{"eval", "as-an-argument", `echo eval`, true},
	{"eval", "in-a-substitution", `x=$( (echo a); eval echo b )`, true},
	{"eval", "in-double-quoted-text", `echo "do not eval this"`, false},
	{"eval", "in-a-child-shell", `sh -c 'eval "$1"' sh true`, false},
	{"eval", "inside-a-longer-word", `./evaluate && medieval`, false},

	// 2. trap, unless it resets or names only other signals.
	{"trap", "exit", `trap 'rm -f "$t"' EXIT`, true},
	{"trap", "exit-lowercase", `trap 'rm -f "$t"' exit`, true},
	{"trap", "exit-sig-prefixed", `trap 'rm -f "$t"' SIGEXIT`, true},
	{"trap", "exit-by-number", `trap 'rm -f "$t"' 0`, true},
	{"trap", "exit-by-padded-number", `trap 'rm -f "$t"' 00`, true},
	{"trap", "exit-quoted", `trap 'rm -f "$t"' "EXIT"`, true},
	{"trap", "exit-among-others", `trap 'rm -f "$t"' INT EXIT`, true},
	{"trap", "exit-after-a-redirection", `trap 'rm -f "$t"' TERM >/dev/null EXIT`, true},
	{"trap", "signal-from-a-variable", `sig=EXIT; trap 'echo x' $sig`, true},
	{"trap", "handler-unquoted", `trap cleanup EXIT`, true},
	{"trap", "handler-double-quoted", `trap "rm -f $t" TERM`, true},
	{"trap", "after-an-operator", `make && trap 'x' EXIT`, true},
	{"trap", "in-a-subshell", `( trap 'x' EXIT; make )`, true},
	{"trap", "in-a-substitution", `x=$(trap : EXIT; echo y)`, true},
	{"trap", "as-an-argument", `echo trap 'x' EXIT`, true},
	{"trap", "bare", `trap`, true},
	{"trap", "one-operand", `trap EXIT`, true},
	{"trap", "second-on-the-line", `trap - EXIT; trap 'x' EXIT`, true},
	{"trap", "reset", `trap - EXIT`, false},
	{"trap", "reset-after-separator", `trap -- - EXIT INT`, false},
	{"trap", "term", `trap 'echo stopping' TERM`, false},
	{"trap", "int-term-then-a-command", `trap 'echo stopping' INT TERM; make`, false},
	{"trap", "numbered", `trap 'echo' 10`, false},
	{"trap", "quoted-signal", `trap 'echo stopping' "TERM"`, false},
	{"trap", "lowercase-sig-prefixed", `trap 'echo stopping' sigterm`, false},
	{"trap", "in-double-quoted-text", `echo "a; trap 'x' EXIT"`, false},
	{"trap", "in-a-child-shell", `sh -c 'trap "rm -f x" EXIT; make'`, false},
	{"trap", "in-a-double-quoted-child-shell", `sh -c "trap 'rm -f x' EXIT; make"`, false},
	{"trap", "after-a-comment-mark", `make # then trap 'x' EXIT`, false},
	{"trap", "inside-a-longer-word", `./entrapment --strap`, false},

	// 3. A command that begins with an expansion and names no file.
	{"command", "variable", `$SUDO make install`, true},
	{"command", "quoted-variable", `"$cmd" --version`, true},
	{"command", "positional", `"$@"`, true},
	{"command", "braced", `${RUNNER} test`, true},
	{"command", "substitution", `$(command -v sh) -c true`, true},
	{"command", "backtick", "`command -v sh` -c true", true},
	{"command", "after-an-operator", `make && $run`, true},
	{"command", "after-a-keyword", `if $ok; then :; fi`, true},
	{"command", "after-an-assignment", `FOO=1 $run`, true},
	{"command", "after-command", `command $tool`, true},
	{"command", "path-from-a-variable", `"$bin/assay" version`, false},
	{"command", "path-unquoted", `$HOME/.local/bin/assay version`, false},
	{"command", "expansion-as-an-argument", `echo "$x" $y`, false},
	{"command", "expansion-in-a-test", `[ "$x" = y ] && echo same`, false},
	{"command", "assignment-only", `x=$y`, false},
	{"command", "exported-path", `export PATH="$HOME/bin:$PATH"`, false},

	// 4. The mktemp assignment.
	{"mktemp", "plain", `t=$(mktemp)`, true},
	{"mktemp", "quoted", `t="$(mktemp -d)"`, true},
	{"mktemp", "padded", `t=$( mktemp )`, true},
	{"mktemp", "backtick", "t=`mktemp`", true},
	{"mktemp", "with-an-environment", `t=$(TMPDIR=/x mktemp)`, true},
	{"mktemp", "through-command", `t=$(command mktemp)`, true},
	{"mktemp", "as-a-default", `t=${T:-$(mktemp)}`, true},
	{"mktemp", "exported", `export t=$(mktemp)`, true},
	{"mktemp", "exported-quoted", `export "t=$(mktemp)"`, true},
	{"mktemp", "after-an-operator", `true&&t=$(mktemp)`, true},
	{"mktemp", "after-a-semicolon", `set -e;t=$(mktemp)`, true},
	{"mktemp", "after-a-quoted-apostrophe", `y="it's" t=$(mktemp)`, true},
	{"mktemp", "printed-as-name-value", `echo "report=$(mktemp)" >> "$GITHUB_OUTPUT"`, true},
	{"mktemp", "install-one-liner", `sh -c 't=$(mktemp) && curl -sSfL -o "$t" https://example.test/install.sh && sh "$t"; s=$?; rm -f "$t"; exit $s'`, false},
	{"mktemp", "printed-text", `printf '%s\n' 't=$(mktemp)'`, false},
	{"mktemp", "not-assigned", `rm -f "$(mktemp)"`, false},

	// Not claimed: spellings built to hide the word. Accepted, and bash
	// sets the EXIT trap for each.
	{"hidden", "escaped-letter", `e\val 'trap : EXIT'`, false},
	{"hidden", "empty-quotes-inside-the-word", `tr""ap 'x' EXIT`, false},
	{"hidden", "word-finished-by-a-variable", `c=ap; tr$c : EXIT`, false},
	{"hidden", "sourced-file", `. ./lib.sh`, false},
}

// TestLeakGuard_RefusesOnSight drives both entry points the document tests
// use -- the decoded run scalar (firstShellLeak) and the install job of a
// document (leakedInInstallJob) -- over leakRows.
func TestLeakGuard_RefusesOnSight(t *testing.T) {
	for _, tc := range leakRows {
		t.Run(tc.group+"/"+tc.name, func(t *testing.T) {
			if got := firstShellLeak(tc.script) != ""; got != tc.refused {
				t.Errorf("decoded run refused = %v, want %v: %s", got, tc.refused, tc.script)
			}
			if got := leakedInInstallJob(tc.script) != ""; got != tc.refused {
				t.Errorf("install job refused = %v, want %v: %s", got, tc.refused, tc.script)
			}
		})
	}
}

// TestLeakGuard_ReadsTheDocument holds what reads the document rather than
// the shell: backslash continuation, YAML folding and unquoting, comments.
// The lines are what the review rounds of PR #327 and main QA of 4d823d1
// found misread.
func TestLeakGuard_ReadsTheDocument(t *testing.T) {
	for _, tc := range []struct {
		text    string
		refused bool
	}{
		// YAML quoting is removed before sh's.
		{`    - "cd \"$D\" && trap 'x' EXIT"`, true},
		{`    - 'trap ''rm -f "$t"'' EXIT'`, true},
		{`    - "trap 'x' EXIT" # note`, true},
		{`    - 't=$(mktemp)' # note`, true},
		{`  before_script: trap 'rm -f "$t"' EXIT`, true},
		{`  script: ["t=$(mktemp)", "trap 'x' EXIT"]`, true},
		{`  script: [ "echo one", "trap 'x' EXIT" ]`, true},
		{`      - run: trap 'x' EXIT`, true},
		{`  script: [ "echo one", "echo two" ]`, false},
		{`  image: alpine:3.20`, false},
		// A mapping value that is not a script is not a command line, so an
		// expansion at its start is a value. The other rules still read it.
		{`  IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA`, false},
		{`    - if: $CI_COMMIT_TAG`, false},
		{`    key: "$CI_JOB_NAME"`, false},
		{`  script: $run`, true},
		{`    - $run`, true},
		{`    - run: $run`, true},
		{`  NOTE: eval is refused here too`, true},
		// A README line is sh, not YAML: one quoted word is a command of
		// that name.
		{`"trap 'x' EXIT"`, false},
		{`"$CI_PROJECT_DIR/setup" && trap 'rm -f "$t"' "EXIT"`, true},
		{"```bash\ntrap 'x' EXIT\n```", true},
		{"```bash\necho done\n```", false},
		// Continued and folded lines are one line.
		{"    - |\n      trap 'rm -f \"$t\"' \\\n        EXIT", true},
		{"    - |\n      t=$(\\\n        mktemp)", true},
		{"    - |\n      trap 'rm -f \"$t\"; \\\n        echo done' EXIT", true},
		{"    - >\n      trap 'rm -f \"$t\"'\n      EXIT", true},
		{"  before_script: >-\n    t=$(mktemp)", true},
		{"    - >\n      trap 'echo stopping'\n      TERM", false},
		// Only a backslash immediately before the newline continues a
		// line, and never from inside a comment.
		{"    - |\n      echo safe\\ \n      trap 'echo cleanup' EXIT", true},
		{"    - |\n      echo safe\\\t\n      trap 'echo cleanup' EXIT", true},
		{"    - |\n      echo safe\\\n      trap 'echo cleanup' EXIT", false},
		{"    # example ending in backslash \\\n    - trap 'echo catch-me' EXIT", true},
		{"    - make # note \\\n    - trap 'echo catch-me' EXIT", true},
		{"    - make;# note \\\n    - trap 'echo catch-me' EXIT", true},
		{"    - (make)# note \\\n    - trap 'echo catch-me' EXIT", true},
		// $(date)#tag is one word, so its line still continues.
		{"    - |\n      echo $(date)#tag; trap 'echo cleanup' TERM \\\n        EXIT", true},
		// A comment is not read.
		{`    # see note; trap 'x' EXIT`, false},
		{`    - make # then trap 'x' EXIT`, false},
	} {
		if got := leakedIntoJob.MatchString(tc.text); got != tc.refused {
			t.Errorf("refused = %v, want %v for %q", got, tc.refused, tc.text)
		}
	}
	// The decoded run scalar joins sh's continuation too.
	if firstShellLeak("echo ok\ntrap 'echo cleanup' TERM \\\n  EXIT") == "" {
		t.Error("a signal continued onto the next line of a run scalar is not read")
	}
	if got := firstShellLeak("make # note \\\ntrap 'echo stopping' TERM"); got != "" {
		t.Errorf("a comment's backslash joined the next line of a run scalar: %q", got)
	}
}

// TestLeakGuard_HostileLines holds that no line panics the guard or costs
// more than a moment: it runs on whatever a document holds.
func TestLeakGuard_HostileLines(t *testing.T) {
	const size = 100 << 10
	repeat := func(unit string) string { return strings.Repeat(unit, size/len(unit)+1) }
	lines := map[string]string{
		"unterminated single quote":   "echo 'never closed",
		"unterminated double quote":   `echo "never closed`,
		"unterminated substitution":   `echo "$(date`,
		"unterminated braces":         `echo ${x:-`,
		"lone backslash":              `\`,
		"lone dollar":                 `$`,
		"lone redirection":            `>`,
		"long plain line":             repeat("word "),
		"long quoted line":            "echo '" + repeat("x") + "'",
		"long unterminated quote":     `echo "` + repeat("x"),
		"long run of traps":           repeat("trap "),
		"long run of TERM traps":      repeat("trap 'echo' TERM; "),
		"deep substitutions":          repeat("$("),
		"deep quoted substitutions":   repeat(`"$(`),
		"deep braces":                 repeat("${x:-"),
		"long run of parentheses":     repeat("()"),
		"long run of comment starts":  repeat(")#") + `\`,
		"long run of redirections":    repeat("2>&1 "),
		"long run of escaped quotes":  repeat(`\'`),
		"long run of mktemp prefixes": repeat("t=$( "),
	}
	start := time.Now()
	for _, line := range lines {
		// Either answer is fine; returning at all is the assertion.
		firstShellLeak(line)
		leakedIntoJob.FindString("    - " + line)
		leakedIntoJob.FindString("  script: [" + line + "]")
	}
	if spent := time.Since(start); spent > 5*time.Second {
		t.Errorf("the hostile lines took %v", spent)
	}
}
