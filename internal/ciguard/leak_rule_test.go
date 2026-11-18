package ciguard

import (
	"strings"
	"testing"
	"time"
)

// leakRows is the rule's contract, one row per branch of it and per
// historical false positive rather than one per spelling. keeps is what Git
// Bash 5.2 does with the script: true when an EXIT trap is still set at its
// end, or the variable t still names a mktemp path. refused is what the
// guard must say. A row that keeps and is not refused is a leak the guard
// accepts, and is allowed in the "documented miss" group only -- the list in
// leakGuard's comment, held here so it cannot drift.
var leakRows = []struct {
	group, name, script string
	keeps, refused      bool
}{
	// 1. eval, wherever it stands and whatever it would run.
	{"eval", "literal", `eval "trap 'echo x' EXIT"`, true, true},
	{"eval", "stored", `cleanup='trap "echo cleanup" EXIT'; eval "$cleanup"`, true, true},
	{"eval", "requoted", `e\val 'trap : EXIT'`, true, true},
	{"eval", "after-command", `command eval 'trap : EXIT'`, true, true},
	{"eval", "harmless", `c='echo ok'; eval "$c"`, false, true},
	{"eval", "of-an-unset-variable", `eval "$cleanup"`, false, true},
	{"eval", "as-an-argument", `echo eval`, false, true},

	// 2. trap, unless it resets or names only other signals.
	{"trap", "exit", `trap 'rm -f "$t"' EXIT`, true, true},
	{"trap", "zero", `trap : 0`, true, true},
	{"trap", "lowercase", `trap : exit`, true, true},
	// bash takes the SIG prefix on EXIT in POSIX mode only.
	{"trap", "sig-prefixed", `set -o posix; trap : sigexit`, true, true},
	{"trap", "quoted-signal", `trap : "EX"IT`, true, true},
	{"trap", "among-other-signals", `trap : INT TERM EXIT`, true, true},
	{"trap", "plus-zero", `trap : +0`, true, true},
	{"trap", "padded-zero", `trap : ' 0'`, true, true},
	{"trap", "signal-from-a-variable", `sig=EXIT; trap : $sig`, true, true},
	{"trap", "signal-from-a-variable-harmless", `sig=TERM; trap : $sig`, false, true},
	{"trap", "signals-from-braces", `trap : {EXIT,TERM}`, true, true},
	{"trap", "one-operand-that-splits", `a='echo EXIT'; trap $a`, true, true},
	{"trap", "in-a-function-body", `f() { trap : EXIT; }; f`, true, true},
	{"trap", "in-a-case-arm", `case x in x)trap : EXIT;; esac`, true, true},
	{"trap", "after-a-redirection", `>/dev/null trap : EXIT`, true, true},
	{"trap", "after-an-array-assignment", `a=(1 2) trap : EXIT`, true, true},
	{"trap", "inside-another-handler", `trap 'trap : EXIT' DEBUG; true`, true, true},
	{"trap", "handler-from-a-variable", `h='trap : EXIT'; trap "echo; $h" DEBUG; true`, true, true},
	{"trap", "handler-from-a-variable-harmless", `trap "echo $HOME" TERM`, false, true},
	{"trap", "after-an-escaped-dollar-and-quote", `echo \$'a\' ; trap : EXIT ; echo \'`, true, true},
	{"trap", "after-an-ansi-c-string", `echo $'a\'' ; trap : EXIT ; echo 'b' "'" #"`, true, true},
	{"trap", "after-a-hash-inside-a-word", `echo a#b; trap : EXIT`, true, true},
	{"trap", "after-a-parenthesis-inside-braces", `echo $(echo ${x:-(}) ; trap : EXIT`, true, true},
	{"trap", "in-a-subshell", `( trap : EXIT )`, false, true},
	{"trap", "as-an-argument", `echo trap x EXIT`, false, true},
	{"trap", "printed", `trap -p EXIT`, false, true},

	// 3. a command word that is not written out.
	{"command word", "variable", `c=trap; $c : EXIT`, true, true},
	{"command word", "quoted-variable", `c=trap; "$c" : EXIT`, true, true},
	{"command word", "braced-variable", `c=trap; ${c} : EXIT`, true, true},
	{"command word", "variable-inside-the-word", `c=ap; tr$c : EXIT`, true, true},
	{"command word", "substitution", `$(echo trap) : EXIT`, true, true},
	{"command word", "backtick", "`echo trap` : EXIT", true, true},
	{"command word", "positional-parameters", `set -- trap : EXIT; "$@"`, true, true},
	{"command word", "ansi-c-string", `$'tr\x61p' : EXIT`, true, true},
	{"command word", "brace-expansion", `{trap,:,EXIT}`, true, true},
	{"command word", "after-an-assignment", `c=trap; X=1 $c : EXIT`, true, true},
	{"command word", "after-command", `c=trap; command $c : EXIT`, true, true},
	{"command word", "after-a-bang", `c=trap; ! $c : EXIT`, true, true},
	{"command word", "after-if", `c=trap; if $c : EXIT; then :; fi`, true, true},
	{"command word", "after-a-redirection", `c=trap; 2>&1 $c : EXIT`, true, true},
	{"command word", "in-a-function-keyword-body", `c=trap; function g { $c : EXIT; }; g`, true, true},
	{"command word", "after-time", `c=trap; time -p $c : EXIT`, true, true},
	{"command word", "after-builtin", `c=trap; builtin $c : EXIT`, true, true},
	{"command word", "after-command-options", `c=trap; command -p -- $c : EXIT`, true, true},
	{"command word", "after-array-assignments", `c=trap; a[0]=1 b+=x $c : EXIT`, true, true},
	{"command word", "after-a-semicolon", `c=trap; true; $c : EXIT`, true, true},
	{"command word", "after-and", `c=trap; true && $c : EXIT`, true, true},
	{"command word", "after-or", `c=trap; false || $c : EXIT`, true, true},
	{"command word", "in-a-case-arm", `c=trap; case x in x) $c : EXIT;; esac`, true, true},
	{"command word", "after-then", `c=trap; if true; then $c : EXIT; fi`, true, true},
	{"command word", "after-else", `c=trap; if false; then :; else $c : EXIT; fi`, true, true},
	{"command word", "after-elif", `c=trap; if false; then :; elif $c : EXIT; then :; fi`, true, true},
	{"command word", "after-while", `c=trap; while $c : EXIT; do break; done`, true, true},
	{"command word", "after-until", `c=trap; until ! $c : EXIT; do break; done`, true, true},
	{"command word", "after-do", `c=trap; for i in 1; do $c : EXIT; done`, true, true},
	{"command word", "slash-only-inside-braces", `c=trap; ${c:-/bin/true} : EXIT`, true, true},
	{"command word", "harmless", `SUDO=; $SUDO true`, false, true},

	// 4. the mktemp assignment.
	{"mktemp", "plain", `t=$(mktemp)`, true, true},
	{"mktemp", "quoted", `t="$(mktemp -d)"`, true, true},
	{"mktemp", "backtick", "t=`mktemp`", true, true},
	{"mktemp", "exported", `export t=$(mktemp)`, true, true},
	{"mktemp", "exported-quoted", `export "t=$(mktemp)"`, true, true},
	{"mktemp", "after-an-operator", `set -e;t=$(mktemp)`, true, true},
	{"mktemp", "after-empty-quotes", `t=''"$(mktemp)"`, true, true},
	{"mktemp", "as-an-argument", `echo t=$(mktemp)`, false, true},
	{"mktemp", "for-one-command", `t=$(mktemp) true`, false, true},

	// What the rule cannot pair is refused, not guessed at. The first three
	// hide a real trap from a reader that guesses.
	{"unpaired", "string-across-lines", "echo 'a\nb'; trap : EXIT", true, true},
	{"unpaired", "quote-inside-braces", `echo "${x#'"'}" ; trap : EXIT ; echo "'" #"`, true, true},
	{"unpaired", "case-inside-a-substitution", `echo $(case a in a) echo y;; esac)#x; trap : EXIT`, true, true},
	{"unpaired", "quote-inside-braces-harmless", `echo "${1:-"default"}"`, false, true},
	{"unpaired", "quote-inside-braces-inside-a-substitution", `echo $(echo ${x:-"a"})`, false, true},
	{"unpaired", "backtick-harmless", "echo \"`date`\"", false, true},
	// bash 5.3 runs this in the calling shell; Git Bash 5.2 rejects it.
	{"unpaired", "substitution-in-this-shell", `x=${ trap : EXIT; }`, false, true},

	// Accepted on purpose. The trap rows are the historical false
	// positives (main QA of 67e2cf6); the quoted ones are main QA of
	// 4d823d1's.
	{"accepted", "reset", `trap - EXIT`, false, false},
	{"accepted", "reset-after-separator", `trap -- - EXIT`, false, false},
	{"accepted", "reset-posix", `trap EXIT`, false, false},
	{"accepted", "term-trap", `trap 'echo stopping' TERM`, false, false},
	{"accepted", "int-term-trap", `trap 'cleanup' INT TERM`, false, false},
	{"accepted", "term-trap-redirected", `trap 'echo stopping' TERM 2>/dev/null`, false, false},
	{"accepted", "quoted-numbered-and-lowercase-signals", `trap -- 'echo' "TERM" '10' int`, false, false},
	{"accepted", "listing", `trap`, false, false},
	{"accepted", "path-from-a-variable", `"$bin/assay" version`, false, false},
	{"accepted", "path-from-an-unquoted-variable", `$HOME/bin/assay version`, false, false},
	{"accepted", "path-from-a-substitution", `"$(pwd)/bin/assay" version`, false, false},
	{"accepted", "path-from-a-default", `"${RUNNER_TEMP:-/tmp}/assay-tool" version`, false, false},
	{"accepted", "child-shell", `sh -c 'd=$(mktemp -d); trap "rm -rf $d" EXIT; echo child'`, false, false},
	{"accepted", "install-one-liner", `sh -c 't=$(mktemp) && curl -sSfL -o "$t" https://example.invalid/install.sh && sh "$t" -b /usr/local/bin; s=$?; rm -f "$t"; exit $s'`, false, false},
	{"accepted", "printed-text", `printf '%s' 'No install - run t=$(mktemp) first'`, false, false},
	{"accepted", "double-quoted-text", `echo "a; trap 'x' EXIT"`, false, false},
	{"accepted", "apostrophe-in-double-quotes", `echo "it's done"`, false, false},
	{"accepted", "single-quoted-text", `echo 'no trap here; eval nothing'`, false, false},
	{"accepted", "stored-but-never-run", `cleanup='trap echo EXIT'`, false, false},
	{"accepted", "trap-in-a-substitution", `x=$(trap : EXIT; echo y)`, false, false},
	{"accepted", "test-and-redirection", `if [ ! -s "$report" ]; then echo "sarif=$report" >> "${GITHUB_OUTPUT:-/dev/null}"; fi`, false, false},
	{"accepted", "case-on-a-substitution", `case "$(uname -s)" in Linux|Darwin) echo u;; *) echo o;; esac`, false, false},
	{"accepted", "quotes-inside-a-quoted-substitution", `echo "signing key is $(basename "$k")"; sleep $((1 - 1))`, false, false},
	{"accepted", "loop", `for f in a b; do echo "$f"; done`, false, false},
	{"accepted", "command-v", `command -v "$tool" >/dev/null`, false, false},
	{"accepted", "assignment-then-argument", `report_dir="assay-reports-$CI_JOB_ID"; mkdir "$report_dir"`, false, false},
	{"accepted", "backticks-in-single-quotes", "echo '```'", false, false},
	{"accepted", "braces-as-an-argument", `find . -name x -exec echo {} \;`, false, false},
	{"accepted", "redirection-first", `>"$log" echo started`, false, false},
	{"accepted", "subshell-inside-a-substitution", `x=$( (echo a); eval echo b )`, false, false},

	// Leaks the guard accepts: the list in leakGuard's comment.
	{"documented miss", "alias", "shopt -s expand_aliases\nalias t=trap\nt : EXIT", true, false},
	{"documented miss", "sourced-file", `printf '%s\n' 'trap : EXIT' > lib.sh; . ./lib.sh`, true, false},
	{"documented miss", "sourced-substitution", `source <(printf '%s\n' 'trap : EXIT')`, true, false},
	{"documented miss", "function-defined-elsewhere", `printf '%s\n' 'setup_cleanup() { trap : EXIT; }' > lib.sh; . ./lib.sh; setup_cleanup`, true, false},
	{"documented miss", "mapfile-callback", `printf '%s\n' x > lines.txt; mapfile -C 'trap : EXIT #' -c 1 < lines.txt`, true, false},
	{"documented miss", "split-ahead-of-a-slash", `p='trap : EXIT '; $p/x`, true, false},
	{"documented miss", "glob-command-word", `touch trap; tra? : EXIT`, true, false},
	{"documented miss", "mktemp-through-read", `read -r t < <(mktemp)`, true, false},
	{"documented miss", "mktemp-behind-another-command", `t=$(env mktemp)`, true, false},
}

// TestLeakGuard_RefusesOnSight drives both entry points the document tests
// use -- the decoded run scalar (firstShellLeak) and the install job of a
// document (leakedInInstallJob) -- over leakRows.
func TestLeakGuard_RefusesOnSight(t *testing.T) {
	misses := 0
	for _, tc := range leakRows {
		t.Run(tc.group+"/"+tc.name, func(t *testing.T) {
			if got := firstShellLeak(tc.script) != ""; got != tc.refused {
				t.Errorf("decoded run refused = %v, want %v: %s", got, tc.refused, tc.script)
			}
			if got := leakedInInstallJob(tc.script) != ""; got != tc.refused {
				t.Errorf("install job refused = %v, want %v: %s", got, tc.refused, tc.script)
			}
			if miss := tc.keeps && !tc.refused; miss != (tc.group == "documented miss") {
				t.Errorf("a leak the guard accepts belongs in the documented misses, and only such a row does: %s", tc.script)
			}
		})
		if tc.group == "documented miss" {
			misses++
		}
	}
	// The comment's list has six entries; three are pinned by more than one
	// row (two ways to source, two ways past mktempAssign).
	if misses != 9 {
		t.Errorf("%d documented-miss rows, want 9: change leakGuard's comment with them", misses)
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
	for name, line := range map[string]string{
		"unterminated single quote": lines["unterminated single quote"],
		"unterminated double quote": lines["unterminated double quote"],
		"unterminated substitution": lines["unterminated substitution"],
		"unterminated braces":       lines["unterminated braces"],
		"deep substitutions":        lines["deep substitutions"],
	} {
		if firstShellLeak(line) == "" {
			t.Errorf("%s: a line the rule cannot pair is accepted", name)
		}
	}
}
