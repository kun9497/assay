package ciguard

import (
	"strings"
	"testing"
	"time"
)

// leakShapes are the shapes the guard is held to on both of its paths. keeps
// is what Git Bash 5.2 answers for the script followed by `trap -p EXIT`: true
// when the calling shell is left holding an EXIT trap. A row refused with
// keeps false is a deliberate refusal -- the guard cannot tell, so it is loud.
// A row accepted with keeps true would be a miss; there is none.
var leakShapes = []struct {
	name, script   string
	refused, keeps bool
}{
	// A string eval could not parse runs none of its line, so its
	// reassignment never happened and the trap is still what the name holds.
	{"eval-then-first", `cleanup='trap "echo LEAK" EXIT'; eval 'then; cleanup="echo safe"' || :; eval "$cleanup"`, true, true},
	{"eval-if-missing-then", `cleanup='trap "echo LEAK" EXIT'; eval 'if true; fi; cleanup="echo safe"' || :; eval "$cleanup"`, true, true},
	{"eval-while-missing-do", `cleanup='trap "echo LEAK" EXIT'; eval 'while false; done; cleanup="echo safe"' || :; eval "$cleanup"`, true, true},
	{"eval-stray-close-paren", `cleanup='trap "echo LEAK" EXIT'; eval 'cleanup="echo safe"; )' || :; eval "$cleanup"`, true, true},
	{"eval-leading-semicolon", `cleanup='trap "echo LEAK" EXIT'; eval '; cleanup="echo safe"' || :; eval "$cleanup"`, true, true},
	{"eval-double-semicolon", `cleanup='trap "echo LEAK" EXIT'; eval 'cleanup="echo safe";; ' || :; eval "$cleanup"`, true, true},
	{"eval-unterminated-quote", `cleanup='trap "echo LEAK" EXIT'; eval 'cleanup="echo safe"; echo "' || :; eval "$cleanup"`, true, true},
	{"eval-trailing-open-paren", `cleanup='trap "echo LEAK" EXIT'; eval 'cleanup="echo safe"; (' || :; eval "$cleanup"`, true, true},
	{"eval-stray-do", `cleanup='trap "echo LEAK" EXIT'; eval 'cleanup="echo safe"; do' || :; eval "$cleanup"`, true, true},
	{"eval-stray-esac", `cleanup='trap "echo LEAK" EXIT'; eval 'cleanup="echo safe"; esac' || :; eval "$cleanup"`, true, true},
	{"eval-empty-pipeline", `cleanup='trap "echo LEAK" EXIT'; eval 'cleanup="echo safe"; | |' || :; eval "$cleanup"`, true, true},
	{"eval-unclosed-if-after-assignment", `cleanup='trap "echo LEAK" EXIT'; eval 'cleanup="echo safe"; if true; then :' || :; eval "$cleanup"`, true, true},
	{"eval-unclosed-brace-after-assignment", `cleanup='trap "echo LEAK" EXIT'; eval 'cleanup="echo safe"; { :' || :; eval "$cleanup"`, true, true},
	{"eval-trailing-or-after-assignment", `cleanup='trap "echo LEAK" EXIT'; eval 'cleanup="echo safe"; true ||' || :; eval "$cleanup"`, true, true},
	{"eval-unset-in-malformed-string", `cleanup='trap "echo LEAK" EXIT'; eval 'unset cleanup; )' || :; eval "$cleanup"`, true, true},
	// The same rule on a string that did parse: what eval assigned is unknown.
	{"eval-assignment-is-unknown", `cleanup='trap "echo LEAK" EXIT'; eval 'cleanup="echo safe"'; eval "$cleanup"`, true, false},
	{"eval-unset-is-unknown", `cleanup='trap "echo LEAK" EXIT'; eval 'unset cleanup'; eval "$cleanup"`, true, false},
	{"eval-assignment-then-known-reassign", `cleanup='trap "echo LEAK" EXIT'; eval 'cleanup="echo safe"; )' || :; cleanup='echo ok'; eval "$cleanup"`, false, false},
	{"eval-of-literal-text", `eval 'echo hi'`, false, false},
	{"eval-of-known-safe-value", `cleanup='echo ok'; eval "$cleanup"`, false, false},

	{"append-signal", `cleanup='trap "echo LEAK"'; cleanup+=' EXIT'; eval "$cleanup"`, true, true},
	{"append-trap", `cleanup='echo ok;'; cleanup+=' trap "echo LEAK" EXIT'; eval "$cleanup"`, true, true},
	{"append-in-export", `cleanup='echo ok;'; export cleanup+=' trap "echo LEAK" EXIT'; eval "$cleanup"`, true, true},

	{"append-before-special-builtin", `cleanup='echo ok;'; cleanup+=' trap : EXIT' :; eval "$cleanup"`, true, false},
	{"case-arm-reassign-multiline", "cleanup='trap \"echo LEAK\" EXIT'\ncase x in\ny)\ncleanup='echo ok'\n;;\nesac\neval \"$cleanup\"", true, true},
	{"case-arm-reassign-one-line", `cleanup='trap "echo LEAK" EXIT'; case x in y) cleanup='echo ok';; esac; eval "$cleanup"`, true, true},
	{"case-arm-sets-trap-multiline", "cleanup='echo ok'\ncase x in\nx)\ncleanup='trap \"echo LEAK\" EXIT'\n;;\nesac\neval \"$cleanup\"", true, true},
	{"case-arm-sets-trap-one-line", `cleanup='echo ok'; case x in x) cleanup='trap "echo LEAK" EXIT';; esac; eval "$cleanup"`, true, true},
	{"case-alternatives-arm-sets-trap", `cleanup='echo ok'; case x in y|x) cleanup='trap "echo LEAK" EXIT';; esac; eval "$cleanup"`, true, true},
	{"case-alternatives-arm-second-command", `cleanup='echo ok'; case x in y|x) :; cleanup='trap "echo LEAK" EXIT';; esac; eval "$cleanup"`, true, true},
	{"case-arm-unset", `cleanup='trap "echo LEAK" EXIT'; case x in y) unset cleanup;; esac; eval "$cleanup"`, true, true},
	{"case-arm-trap", `case x in x) trap 'echo LEAK' EXIT;; esac`, true, true},
	{"case-nested-arm-sets-trap", `cleanup='echo ok'; case x in x) case y in y) cleanup='trap "echo LEAK" EXIT';; esac;; esac; eval "$cleanup"`, true, true},
	{"case-parenthesised-pattern-sets-trap", `cleanup='echo ok'; case x in (x) cleanup='trap "echo LEAK" EXIT';; esac; eval "$cleanup"`, true, true},
	{"case-arm-body-substitution-with-paren", "cleanup='echo ok'\ncase x in\nx)\ncleanup=$(printf '%s' 'trap : EXIT #)')\n;;\nesac\neval \"$cleanup\"", true, true},
	{"case-arm-body-assignment-beside-array", "cleanup='echo ok'\ncase x in\nx)\ncleanup='trap : EXIT' arr=(a b)\n;;\nesac\neval \"$cleanup\"", true, true},
	{"case-arm-body-trap-handler-substitution-with-paren", "cleanup='echo ok'\ncase x in\nx)\ntrap $(printf '%s' ':)') EXIT\n;;\nesac\n:", true, true},
	{"case-arm-body-escaped-paren-argument", "cleanup='echo ok'\ncase x in\nx)\neval 'trap : EXIT #' \\)\n;;\nesac\n:", true, true},
	{"case-arm-body-defines-function", "cleanup='echo ok'\ncase x in\nx)\nf () { cleanup='trap : EXIT'; }\n;;\nesac\ncleanup='echo ok'; f; eval \"$cleanup\"", true, true},
	{"function-subshell-body-after-esac", `case x in y) :;; esac; f() (echo hi)`, true, false},
	{"eval-string-in-case-arm-reads-its-own-commands", `case x in x) eval 'f() (echo hi)';; esac`, true, false},
	{"case-then-known-reassign", `cleanup='trap "echo LEAK" EXIT'; case x in y) cleanup='echo a';; esac; cleanup='echo ok'; eval "$cleanup"`, false, false},
	{"case-without-assignment", `cleanup='echo ok'; case x in x) echo hit;; *) echo miss;; esac; eval "$cleanup"`, false, false},

	{"function-uncalled-reassign", `cleanup='trap "echo LEAK" EXIT'; f() { cleanup='echo ok'; }; eval "$cleanup"`, true, true},
	{"function-uncalled-reassign-multiline", "cleanup='trap \"echo LEAK\" EXIT'\nf() {\ncleanup='echo ok'\n}\neval \"$cleanup\"", true, true},
	{"function-called-sets-trap", `cleanup='echo ok'; f() { cleanup='trap "echo LEAK" EXIT'; }; f; eval "$cleanup"`, true, true},
	{"function-called-after-reassign", `f() { cleanup='trap "echo LEAK" EXIT'; }; cleanup='echo ok'; f; eval "$cleanup"`, true, true},
	{"function-keyword-sets-trap", `cleanup='echo ok'; function f { cleanup='trap "echo LEAK" EXIT'; }; f; eval "$cleanup"`, true, true},
	{"function-spaced-parens-sets-trap", `cleanup='echo ok'; f () { cleanup='trap "echo LEAK" EXIT'; }; f; eval "$cleanup"`, true, true},
	{"function-attached-brace-sets-trap", `cleanup='echo ok'; f(){ cleanup='trap "echo LEAK" EXIT'; }; f; eval "$cleanup"`, true, true},
	{"function-body-on-next-line", "cleanup='echo ok'\nf()\n{\ncleanup='trap \"echo LEAK\" EXIT'\n}\nf\neval \"$cleanup\"", true, true},
	{"function-body-on-next-line-uncalled-reassign", "cleanup='trap \"echo LEAK\" EXIT'\nf()\n{\ncleanup='echo ok'\n}\neval \"$cleanup\"", true, true},
	{"function-body-not-a-group", `cleanup='echo ok'; f() if true; then cleanup='trap : EXIT'; fi; cleanup='echo ok'; f; eval "$cleanup"`, true, true},
	{"function-evals-later-value", `cleanup='echo ok'; f() { eval "$cleanup"; }; cleanup='trap "echo LEAK" EXIT'; f`, true, true},
	{"function-runs-later-value", `cleanup='echo ok'; f() { $cleanup; }; cleanup='trap : EXIT'; f`, true, true},
	{"function-traps", `f() { trap 'echo LEAK' EXIT; }; f`, true, true},
	{"function-keyword-parens-sets-trap", `cleanup='echo ok'; function f () { cleanup='trap "echo LEAK" EXIT'; }; f; eval "$cleanup"`, true, true},
	{"function-spaced-attached-brace-sets-trap", `cleanup='echo ok'; f (){ cleanup='trap "echo LEAK" EXIT'; }; f; eval "$cleanup"`, true, true},
	{"function-evals-later-value-through-stored-eval", `a='eval "$cleanup"'; cleanup='echo ok'; f() { eval "$a"; }; cleanup='trap "echo LEAK" EXIT'; f`, true, true},
	{"function-sets-trap-after-unset", `f() { cleanup='trap : EXIT'; }; unset cleanup; f; eval "$cleanup"`, true, true},
	{"function-keyword-without-assignment", `function f { echo hi; }; f`, false, false},
	{"function-keyword-parens-without-assignment", `function f () { echo hi; }; f`, false, false},
	{"function-spaced-parens-without-assignment", `f () { echo hi; }; f`, false, false},
	{"function-attached-brace-without-assignment", `f(){ echo hi; }; f`, false, false},
	{"function-spaced-attached-brace-without-assignment", `f (){ echo hi; }; f`, false, false},
	{"function-body-on-next-line-without-assignment", "f()\n{\necho hi\n}\nf", false, false},
	{"function-without-assignment", `cleanup='echo ok'; f() { echo hi; }; f; eval "$cleanup"`, false, false},
	{"function-then-assignment-after-group", `f() { echo hi; }; cleanup='trap "echo LEAK" EXIT'; cleanup='echo ok'; eval "$cleanup"`, false, false},

	{"for-body-reaches-next-iteration", `cleanup='echo ok'; for i in 1 2; do eval "$cleanup"; cleanup='trap "echo LEAK" EXIT'; done`, true, true},
	{"while-body-reaches-next-iteration", `cleanup='echo ok'; n=0; while [ $n -lt 2 ]; do eval "$cleanup"; cleanup='trap "echo LEAK" EXIT'; n=$((n+1)); done`, true, true},
	{"until-body-reaches-next-iteration", `cleanup='echo ok'; n=0; until [ $n -ge 2 ]; do eval "$cleanup"; cleanup='trap "echo LEAK" EXIT'; n=$((n+1)); done`, true, true},
	{"loop-body-runs-later-value", `cleanup='echo ok'; for i in 1 2; do $cleanup; cleanup='trap : EXIT'; done`, true, true},
	{"loop-eval-string-reaches-next-iteration", `cleanup='echo ok'; for i in 1 2; do eval 'eval "$cleanup"'; cleanup='trap "echo LEAK" EXIT'; done`, true, true},
	{"loop-not-closed-by-eval-string", `cleanup='echo ok'; for i in 1 2; do eval 'done' || :; eval "$cleanup"; cleanup='trap "echo LEAK" EXIT'; done`, true, true},
	{"loop-opened-in-eval-string-ends-with-it", `eval 'while false; do' || :; cleanup='echo ok'; eval "$cleanup"; cleanup='echo other' `, false, false},
	{"loop-not-replaced-by-eval-string", `cleanup='echo ok'; for i in 1 2; do eval "$cleanup"; eval 'done; for j in 1; do' || :; cleanup='trap "echo LEAK" EXIT'; done`, true, true},
	{"loop-eval-then-assignment-after-done", `cleanup='echo ok'; for i in 1 2; do eval "$cleanup"; done; cleanup='echo other'`, false, false},
	{"loop-then-known-reassign", `cleanup='trap "echo LEAK" EXIT'; for i in 1; do cleanup='echo a'; done; cleanup='echo ok'; eval "$cleanup"`, false, false},
	{"read-loop", `while read -r line; do echo "$line"; done </dev/null`, false, false},

	{"for-variable", `cleanup='echo ok'; for cleanup in 'trap "echo LEAK" EXIT'; do :; done; eval "$cleanup"`, true, true},
	{"read-variable", `cleanup='echo ok'; read -r cleanup <<<'trap "echo LEAK" EXIT'; eval "$cleanup"`, true, true},
	{"printf-v-variable", `cleanup='echo ok'; printf -v cleanup '%s' 'trap "echo LEAK" EXIT'; eval "$cleanup"`, true, true},
	{"printf-v-attached-variable", `cleanup='echo ok'; printf -vcleanup '%s' 'trap "echo LEAK" EXIT'; eval "$cleanup"`, true, true},
	{"default-assignment-expansion", `: "${cleanup:=trap : EXIT}"; eval "$cleanup"`, true, true},
	{"default-assignment-expansion-unset-only", `: "${cleanup=trap : EXIT}"; eval "$cleanup"`, true, true},
	{"printf-without-v", `cleanup='echo ok'; printf '%s\n' cleanup; eval "$cleanup"`, false, false},

	{"eval-command-substitution", `eval "$(printf '%s' 'trap "echo LEAK" EXIT')"`, true, true},
	{"eval-backtick-substitution", "eval \"`printf '%s' 'trap : EXIT'`\"", true, true},

	{"variable-run-as-command", `cleanup='trap : EXIT'; $cleanup`, true, true},
	{"variable-names-the-builtin", `c=trap; $c 'echo LEAK' EXIT`, true, true},
	{"variable-inside-command-word", `c=tr; ${c}ap 'echo LEAK' EXIT`, true, true},
	{"unknown-variable-run-as-command", `c=$(printf trap); $c 'echo LEAK' EXIT`, true, true},
	{"unknown-variable-beside-quote-in-command-word", `a="'"; b=$(printf trap); $a$b 'echo LEAK' EXIT`, true, false},
	{"known-variable-run-as-command", `run='echo build'; $run`, false, false},
	{"known-directory-in-command-word", `dir=/bin; "$dir/echo" hi`, false, false},
	{"known-command-keeps-its-quoted-argument", `sh=sh; $sh -c 'echo hi; trap "echo child" EXIT' `, false, false},
	{"unset-variable-before-command", `$ASSAY_NO_SUCH_PREFIX echo hi`, false, false},

	{"builtin-trap", `builtin trap 'echo LEAK' EXIT`, true, true},
	{"command-trap", `command trap 'echo LEAK' EXIT`, true, true},
	{"command-p-trap", `command -p trap 'echo LEAK' EXIT`, true, true},
	{"builtin-eval", `cleanup='trap "echo LEAK" EXIT'; builtin eval "$cleanup"`, true, true},
	{"command-v-is-a-query", `command -v echo >/dev/null`, false, false},
	{"command-p-regular-command", `command -p echo hi`, false, false},

	{"signal-zero", `trap 'echo LEAK' 0`, true, true},
	{"signal-double-zero", `trap 'echo LEAK' 00`, true, true},
	{"signal-triple-zero", `trap 'echo LEAK' 000`, true, true},
	{"signal-ten", `trap 'echo hup' 10`, false, false},
	{"reset-through-variable", `sig=EXIT; trap - $sig`, false, false},

	// A group in a pipeline or the background runs in a child. Its commands
	// were read as the job shell's, so it is refused when one of them changed
	// what the guard knows, and only then.
	{"piped-group-without-effects", `{ echo a; echo b; } | tee /dev/null`, false, false},
	{"background-group-without-effects", `{ sleep 0; echo hi; } & wait`, false, false},
	{"piped-group-after-pipe-without-effects", `echo a | { cat; echo b; } | cat`, false, false},
	{"if-with-piped-condition", `cleanup='trap "echo LEAK" EXIT'; if false | false; then :; cleanup='echo ok'; fi; eval "$cleanup"`, true, true},
	{"piped-group-after-assignment-without-effects", `x=1; { echo a; echo b; } | tee /dev/null`, false, false},
	{"piped-group-runs-known-variable", `run='echo hi'; { $run; } | cat`, false, false},
	{"default-assignment-in-pipeline-child", `: "${cleanup:=trap : EXIT}" | cat; eval "$cleanup"`, false, false},
	{"special-builtin-prefix-in-pipeline-child", `cleanup='trap "echo LEAK" EXIT'; cleanup='echo ok'; cleanup=x : | cat; eval "$cleanup"`, false, false},
	{"export-in-pipeline-child", `cleanup='echo ok'; export cleanup='trap : EXIT' | cat; eval "$cleanup"`, false, false},
	{"piped-group-unset", `cleanup='trap "echo LEAK" EXIT'; { unset cleanup; } | cat; eval "$cleanup"`, true, true},
	{"piped-group-reassign", `cleanup='trap "echo LEAK" EXIT'; { cleanup='echo safe'; } | cat; eval "$cleanup"`, true, true},
	{"background-group-reassign", `cleanup='trap "echo LEAK" EXIT'; { cleanup='echo safe'; } & wait; eval "$cleanup"`, true, true},
	{"piped-group-read", `cleanup='trap "echo LEAK" EXIT'; { read -r cleanup; } </dev/null | cat; eval "$cleanup"`, true, true},
	{"piped-group-trap-reset", `{ trap - EXIT; } | cat`, true, false},
	{"piped-group-eval", `{ eval 'echo hi'; } | cat`, true, false},
	{"piped-group-close-without-open", `eval '} | cat' || :`, true, false},
	{"piped-group-with-inner-pipeline", `cleanup='trap "echo LEAK" EXIT'; { echo a | cat; cleanup='echo safe'; } | cat; eval "$cleanup"`, true, true},

	{"install-one-liner", `sh -c 't=$(mktemp) && curl -sSfL -o "$t" https://raw.githubusercontent.com/kun9497/assay/0123456789abcdef0123456789abcdef01234567/install.sh && sh "$t" -b /usr/local/bin; s=$?; rm -f "$t"; exit $s'`, false, false},
	{"install-one-liner-with-sudo", `sh -c 't=$(mktemp) && curl -sSfL -o "$t" https://raw.githubusercontent.com/kun9497/assay/0123456789abcdef0123456789abcdef01234567/install.sh && sudo sh "$t" -b /usr/local/bin; s=$?; rm -f "$t"; exit $s'`, false, false},
}

func TestInstallLeakGuardUnknownValues(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range leakShapes {
		if seen[tc.name] {
			t.Fatalf("two rows are named %s", tc.name)
		}
		seen[tc.name] = true
		if tc.keeps && !tc.refused {
			t.Fatalf("%s: a row bash keeps a trap for cannot be an accepted one", tc.name)
		}
		t.Run(tc.name, func(t *testing.T) {
			if got := firstShellLeak(tc.script) != ""; got != tc.refused {
				t.Errorf("decoded run refused=%v, want %v: %s", got, tc.refused, tc.script)
			}
			if got := leakedInInstallJob(tc.script) != ""; got != tc.refused {
				t.Errorf("install job refused=%v, want %v: %s", got, tc.refused, tc.script)
			}
		})
	}
}

// A GitHub Actions run step is a shell of its own: nothing one step set,
// defined or left open is the next step's.
func TestInstallLeakGuardRunStepsStartClean(t *testing.T) {
	for name, doc := range map[string]string{
		"value":         "steps:\n  - run: cleanup='trap echo EXIT'\n  - run: eval \"$cleanup\"\n",
		"unknown":       "steps:\n  - run: cleanup=$(date)\n  - run: eval \"$cleanup\"\n",
		"function body": "steps:\n  - run: f() { cleanup='trap echo EXIT'; }\n  - run: cleanup='echo ok'; eval \"$cleanup\"\n",
		"function read": "steps:\n  - run: f() { eval \"$cleanup\"; }\n  - run: cleanup='echo ok'\n",
		"open loop":     "steps:\n  - run: for i in 1; do eval \"$cleanup\"\n  - run: cleanup='echo ok'\n",
		"open if":       "steps:\n  - run: if true; then\n  - run: cleanup='echo ok'; eval \"$cleanup\"\n",
	} {
		if got := leakedInInstallJob(doc); got != "" {
			t.Errorf("%s: a run step was refused at %q for what another step left", name, got)
		}
	}
}

// The guard reads text a contributor wrote, some of it half-typed: a quote
// that never closes or one very long line must end in an answer, and in time
// that grows with the input rather than with its square.
func TestInstallLeakGuardEndsOnOpenQuotesAndLongLines(t *testing.T) {
	for _, script := range []string{
		`echo "`, `echo '`, "echo `", `echo $(`, `echo ${`, `eval "`, `eval '`, `trap 'x`, `trap "x" "EXIT`,
		`cleanup='trap "x" EXIT`, `eval "$(`, `case x in "`, `f() { '`, `x="$(echo "`, `echo \`,
		"- '", `- "a\`, `[ "a", 'b`, `eval 'eval "eval \"`,
	} {
		firstShellLeak(script)
		leakedInInstallJob(script)
	}
	const size = 100 << 10
	fill := func(unit string) string { return strings.Repeat(unit, size/len(unit)+1) }
	for name, script := range map[string]string{
		"one word":           fill("a"),
		"commands":           fill("echo a; "),
		"pipeline":           fill("a | "),
		"open quote":         `echo "` + fill("a "),
		"open single quote":  `echo '` + fill("a; "),
		"open substitution":  fill("$("),
		"substitutions":      fill("$(a) "),
		"open groups":        fill("{ "),
		"groups":             fill("{ :; }; "),
		"case arms":          "case x in " + fill("a) :;; ") + "esac",
		"comment after word": fill("a)#"),
		"evals":              fill("eval 'x=1'; "),
		"stored evals":       "c='echo ok'; " + fill(`eval "$c"; `),
		"assignments":        fill("a=1 "),
		"functions":          fill("f() { :; }; "),
		"loops":              fill("for i in 1; do :; done; "),
		"flow sequence":      "- [" + fill(`"a", `) + "]",
	} {
		start := time.Now()
		firstShellLeak(script)
		leakedInInstallJob(script)
		if took := time.Since(start); took > 2*time.Second {
			t.Errorf("%s: %d bytes on one line took %v", name, len(script), took)
		}
	}
}
