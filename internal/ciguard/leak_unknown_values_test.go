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
// A row accepted with keeps true would be a miss; those the guard's header
// documents are in leakMisses and nowhere else.
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

	// A keyword spelled as an alternative of a case pattern is a pattern. Every
	// one of these was refused at a09f948; reading reserved words from pipeline
	// stages had made the `done` of done|y) close the case's conditional scope.
	{"case-pattern-done-alternative", `cleanup='trap "echo LEAK" EXIT'; case x in done|y) cleanup='echo ok';; esac; eval "$cleanup"`, true, true},
	{"case-pattern-fi-alternative", `cleanup='trap "echo LEAK" EXIT'; case x in fi|y) cleanup='echo ok';; esac; eval "$cleanup"`, true, true},
	{"case-pattern-done-middle-alternative", `cleanup='trap "echo LEAK" EXIT'; case x in a|done|y) cleanup='echo ok';; esac; eval "$cleanup"`, true, true},
	{"case-pattern-done-spaced-alternative", `cleanup='trap "echo LEAK" EXIT'; case x in done | y) cleanup='echo ok';; esac; eval "$cleanup"`, true, true},
	{"case-pattern-done-alternative-multiline", "cleanup='trap \"echo LEAK\" EXIT'\nstate=x\ncase \"$state\" in\n  done|finished) cleanup='echo ok' ;;\nesac\neval \"$cleanup\"", true, true},
	{"case-pattern-done-alternative-second-arm", `cleanup='trap "echo LEAK" EXIT'; case x in a) :;; done|y) cleanup='echo ok';; esac; eval "$cleanup"`, true, true},
	{"case-pattern-done-alternative-after-fallthrough", `cleanup='trap "echo LEAK" EXIT'; case x in a) :;& done|y) cleanup='echo ok';; esac; eval "$cleanup"`, true, true},
	{"case-pattern-done-alternative-in-loop", `cleanup='trap "echo LEAK" EXIT'; for i in 1; do case x in done|y) cleanup='echo ok';; esac; done; eval "$cleanup"`, true, true},
	{"case-pattern-is-a-substitution", `case x in $(echo x)) trap 'echo LEAK' EXIT;; esac`, true, true},
	{"case-pattern-continued-on-next-line", "cleanup='trap \"echo LEAK\" EXIT'\ncase x in\n  a |\n  y) cleanup='echo ok' ;;\nesac\neval \"$cleanup\"", true, false},
	{"case-parenthesised-pattern-at-line-start-sets-trap", "cleanup='echo ok'\ncase x in\n  (x) cleanup='trap \"echo LEAK\" EXIT' ;;\nesac\neval \"$cleanup\"", true, true},
	{"case-pattern-alternatives-then-known-reassign", `cleanup='trap "echo LEAK" EXIT'; case x in done|y) :;; esac; cleanup='echo ok'; eval "$cleanup"`, false, false},
	{"case-pattern-keyword-alternative-without-assignment", `cleanup='echo ok'; case x in a|b) echo a;; c|done) echo c;; esac; eval "$cleanup"`, false, false},
	{"case-arm-of-two-commands", `cleanup='echo ok'; case x in a|b) echo a; echo b;; esac; eval "$cleanup"`, false, false},
	{"case-nested-then-command", `cleanup='echo ok'; case x in x) case y in y) :;; esac; echo hi;; esac; eval "$cleanup"`, false, false},
	{"case-parenthesised-pattern-at-line-start", "cleanup='echo ok'\ncase x in\n  (y) echo hit ;;\n  (x|z) echo other ;;\nesac\neval \"$cleanup\"", false, false},
	{"case-parenthesised-pattern-alone-on-line", "cleanup='echo ok'\ncase x in\n  (x)\n    echo hit\n    ;;\nesac\neval \"$cleanup\"", false, false},
	{"case-multiline-arms", "cleanup='echo ok'\ncase \"$(uname -s)\" in\n  Linux|Darwin)\n    echo unix\n    echo more\n    ;;\n  MINGW*|MSYS*)\n    echo win ;;\n  *) echo other\nesac\neval \"$cleanup\"", false, false},
	{"case-arm-pipeline", `cleanup='echo ok'; case x in x) echo hi | cat; echo done;; esac; eval "$cleanup"`, false, false},
	{"case-without-arms", `cleanup='echo ok'; case x in esac; eval "$cleanup"`, false, false},

	// A case, a loop or a function opens after then, do, else, { and ! as it does
	// at a command's start.
	{"for-body-case-arm-trap", `for a in x; do case $a in x) trap 'echo LEAK' EXIT;; esac; done`, true, true},
	{"while-body-case-arm-trap", `n=0; while [ $n -lt 1 ]; do n=1; case x in x) trap 'echo LEAK' EXIT;; esac; done`, true, true},
	{"if-body-case-arm-trap", `if true; then case x in x) trap 'echo LEAK' EXIT;; esac; fi`, true, true},
	{"else-body-case-arm-trap", `if false; then :; else case x in x) trap 'echo LEAK' EXIT;; esac; fi`, true, true},
	{"elif-condition-case-arm-trap", `if false; then :; elif case x in x) trap 'echo LEAK' EXIT;; esac; then :; fi`, true, true},
	{"group-case-arm-trap", `{ case x in x) trap 'echo LEAK' EXIT;; esac; }`, true, true},
	{"negated-case-arm-trap", `! case x in x) trap 'echo LEAK' EXIT;; esac`, true, true},
	{"timed-case-arm-trap", `time case x in x) trap 'echo LEAK' EXIT;; esac`, true, true},
	{"if-body-case-arm-sets-trap", `cleanup='echo ok'; if true; then case x in x) cleanup='trap "echo LEAK" EXIT';; esac; fi; eval "$cleanup"`, true, true},
	{"for-body-case-arm-sets-trap", `cleanup='echo ok'; for i in 1; do case x in x) cleanup='trap "echo LEAK" EXIT';; esac; done; eval "$cleanup"`, true, true},
	{"group-case-arm-sets-trap", `cleanup='echo ok'; { case x in x) cleanup='trap "echo LEAK" EXIT';; esac; }; eval "$cleanup"`, true, true},
	{"if-body-function-sets-trap", `cleanup='echo ok'; if true; then f() { cleanup='trap "echo LEAK" EXIT'; }; fi; f; eval "$cleanup"`, true, true},
	{"group-function-sets-trap", `cleanup='echo ok'; { f() { cleanup='trap "echo LEAK" EXIT'; }; }; f; eval "$cleanup"`, true, true},
	{"if-body-function-keyword-sets-trap", `cleanup='echo ok'; if true; then function f { cleanup='trap "echo LEAK" EXIT'; }; fi; f; eval "$cleanup"`, true, true},
	{"function-in-function-sets-trap", `cleanup='echo ok'; f() { g() { cleanup='trap "echo LEAK" EXIT'; }; }; f; g; eval "$cleanup"`, true, true},
	{"if-body-function-traps", `if true; then f() { trap 'echo LEAK' EXIT; }; f; fi`, true, true},
	{"group-function-traps", `{ f() { trap 'echo LEAK' EXIT; }; f; }`, true, true},
	{"if-body-for-variable", `cleanup='echo ok'; if true; then for cleanup in 'trap "echo LEAK" EXIT'; do :; done; fi; eval "$cleanup"`, true, true},
	{"if-body-select-variable", `cleanup='echo ok'; if true; then select cleanup in 'trap : EXIT'; do break; done <<<1 2>/dev/null; fi; eval "$cleanup"`, true, true},
	{"loop-in-loop-reassign", `cleanup='trap "echo LEAK" EXIT'; for i in; do for j in 1; do :; done; cleanup='echo ok'; done; eval "$cleanup"`, true, true},
	{"case-after-assignment", `a=1 case x in x) trap 'echo LEAK' EXIT;; esac`, true, false},
	{"function-named-with-slash", `cleanup='echo ok'; a/b() { cleanup='trap "echo LEAK" EXIT'; }; x=$(printf a); "$x/b"; eval "$cleanup"`, true, true},
	{"function-named-with-equals", `cleanup='echo ok'; function a=b { cleanup='trap "echo LEAK" EXIT'; }; "a=b"; eval "$cleanup"`, true, true},
	{"function-spaced-parens-hyphenated-name", `cleanup='echo ok'; a-b () { cleanup='trap "echo LEAK" EXIT'; }; a-b; eval "$cleanup"`, true, true},
	{"builtin-argument-is-no-loop", `builtin for 2>/dev/null; cleanup='trap "echo LEAK" EXIT'; cleanup='echo ok'; eval "$cleanup"`, false, false},
	{"export-argument-in-pipeline-child-is-no-loop", `export for | cat; cleanup='trap "echo LEAK" EXIT'; cleanup='echo ok'; eval "$cleanup"`, false, false},
	{"command-argument-is-no-loop", `command for 2>/dev/null; cleanup='trap "echo LEAK" EXIT'; cleanup='echo ok'; eval "$cleanup"`, false, false},
	{"export-argument-is-no-loop", `export for; cleanup='trap "echo LEAK" EXIT'; cleanup='echo ok'; eval "$cleanup"`, false, false},
	{"if-body-case-without-assignment", `cleanup='echo ok'; if true; then case x in x) echo hit;; esac; fi; eval "$cleanup"`, false, false},
	{"if-body-function-without-assignment", `if true; then f() { echo hi; }; f; fi`, false, false},

	// EXIT by number as bash's strtoimax reads it, and the option separator of
	// command and builtin.
	{"signal-plus-zero", `trap 'echo LEAK' +0`, true, true},
	{"signal-minus-zero", `trap 'echo LEAK' -0`, true, true},
	{"signal-blank-zero", `trap 'echo LEAK' " 0"`, true, true},
	{"signal-zero-blank", `trap 'echo LEAK' "0 "`, true, true},
	{"signal-plus-double-zero", `trap 'echo LEAK' +00`, true, true},
	{"signal-blank-exit", `trap 'echo LEAK' " EXIT"`, false, false},
	{"signal-plus-one", `trap 'echo hup' +1`, false, false},
	{"signal-plus-exit", `trap 'echo LEAK' +EXIT`, false, false},
	{"signal-hex-zero", `trap 'echo LEAK' 0x0`, false, false},
	{"command-option-separator-trap", `command -- trap 'echo LEAK' EXIT`, true, true},
	{"command-p-option-separator-trap", `command -p -- trap 'echo LEAK' EXIT`, true, true},
	{"command-p-twice-trap", `command -p -p trap 'echo LEAK' EXIT`, true, true},
	{"command-pp-trap", `command -pp trap 'echo LEAK' EXIT`, true, true},
	{"builtin-option-separator-trap", `builtin -- trap 'echo LEAK' EXIT`, true, true},
	{"builtin-command-trap", `builtin command trap 'echo LEAK' EXIT`, true, true},
	{"command-option-separator-eval", `cleanup='trap "echo LEAK" EXIT'; command -- eval "$cleanup"`, true, true},
	{"command-option-separator-regular-command", `command -- echo hi`, false, false},

	// A reference is found in the word as written, before quote removal.
	{"quoted-variable-inside-command-word", `c=tr; "$c"ap 'echo LEAK' EXIT`, true, true},
	{"braced-quoted-variable-inside-command-word", `c=tr; "${c}"ap 'echo LEAK' EXIT`, true, true},
	{"variable-beside-single-quoted-text-in-command-word", `c=tr; $c'ap' 'echo LEAK' EXIT`, true, true},
	{"quoted-variable-inside-eval-word", `c=tr; eval "$c"ap "'echo LEAK'" EXIT`, true, true},
	{"loop-eval-reads-quoted-variable-later", `for i in 1 2; do eval "$c"ap "'echo LEAK'" EXIT; c=tr; done`, true, true},
	{"indirect-variable-run-as-command", `c=trap; n=c; ${!n} 'echo LEAK' EXIT`, true, true},
	{"substitution-run-as-command", `$(printf trap) 'echo LEAK' EXIT`, true, true},
	{"known-value-splits-before-slash", `x='trap : EXIT '; $x/y`, true, true},
	{"known-quoted-variable-inside-command-word", `c=ec; "$c"ho hi`, false, false},

	// A command word with a literal / in it is a path, whatever the expansion
	// beside it holds: a09f948 accepted these and the unknown-value rule had
	// refused them. Without one the word may be a builtin's name, and stays
	// refused.
	{"path-under-variable-holding-home", `bin="$HOME/.local/bin"; mkdir -p "$bin"; "$bin/assay" version`, false, false},
	{"path-under-variable-holding-substitution", `bin=$(go env GOPATH)/bin; "$bin/assay" version`, false, false},
	{"path-under-default-assignment", `: "${GOBIN:=$HOME/go/bin}"; "$GOBIN/assay" version`, false, false},
	{"path-under-variable-unquoted", `bin=$(go env GOPATH)/bin; $bin/assay version`, false, false},
	{"path-under-default-assignment-unquoted", `: "${GOBIN:=$HOME/go/bin}"; $GOBIN/assay version`, false, false},
	{"path-under-substitution", `"$(go env GOPATH)/bin/assay" version`, false, false},
	{"path-under-substitution-unquoted", `$(go env GOPATH)/bin/assay version`, false, false},
	{"path-under-default-word", `${RUNNER_TEMP_NONE:-/bin}/echo hi`, false, false},
	{"quoted-assignment-like-command-word", `x=$(date); "t=$x" || true`, false, false},
	{"workflow-expression-as-command-word", `${{ inputs.setup }} echo hi`, false, false},
	{"sudo-prefix-from-substitution", `SUDO=$(command -v sudo || true); $SUDO make install`, true, false},
	{"sudo-prefix-assigned-in-a-branch", `SUDO=; [ "$(id -u)" = 0 ] || SUDO=sudo; $SUDO true`, true, false},
	{"shell-from-substitution", `sh=$(command -v sh); $sh -c 'echo hi'`, true, false},
	{"tool-from-substitution", `ASSAY=$(command -v assay); $ASSAY version`, true, false},
	{"substitution-without-path-as-command-word", `$(command -v sh) -c 'echo hi'`, true, false},

	// Names written where the reader had not looked, and text it does not have.
	{"eval-default-of-name-never-assigned", `eval "${cleanup:-trap : EXIT}"`, true, true},
	{"eval-default-of-name-never-assigned-unquoted", `eval ${cleanup-trap : EXIT}`, true, true},
	{"eval-default-beside-text", `eval "${cleanup:-trap} : EXIT"`, true, true},
	{"eval-default-holding-stored-name", `c='trap : EXIT'; eval "${none:-$c}"`, true, true},
	{"default-as-command-word", `${c:-trap} 'echo LEAK' EXIT`, true, true},
	{"empty-default-before-command", `${c:-} trap 'echo LEAK' EXIT`, true, true},
	{"default-holding-stored-name-as-command-word", `c=trap; ${none:-$c} : EXIT`, true, true},
	{"default-holding-substitution-as-command-word", `${none:-$(printf trap)} 'echo LEAK' EXIT`, true, true},
	{"eval-default-without-trap", `eval "${cleanup:-echo ok}"`, false, false},
	{"eval-empty-default", `eval "${EXTRA_SETUP_NONE:-}"`, false, false},
	{"alternative-word-as-command-prefix", `${SUDO_CMD_NONE:+sudo} true`, false, false},
	{"read-without-name", `read <<<'trap : EXIT'; eval "$REPLY"`, true, true},
	{"read-name-in-expansion", `x=cleanup; read -r $x <<<'trap : EXIT'; eval "$cleanup"`, true, true},
	{"read-name-in-expansion-harmless", `x=line; read -r "$x" </dev/null; echo hi`, true, false},
	{"printf-v-name-in-expansion", `x=cleanup; printf -v "$x" '%s' 'trap : EXIT'; eval "$cleanup"`, true, true},
	{"printf-v-name-in-expansion-harmless", `x=out; printf -v "$x" '%s' hi; echo "$out"`, true, false},
	{"read-with-name-leaves-reply", `REPLY='echo ok'; read -r line </dev/null; eval "$REPLY"`, false, false},
	{"read-with-prompt", `read -r -p "Continue? " answer </dev/null; echo "$answer"`, false, false},
	{"array-element-assignment", `cleanup[0]='trap : EXIT'; eval "$cleanup"`, true, true},
	{"array-element-assignment-over-known", `cleanup='echo ok'; cleanup[0]='trap : EXIT'; eval "$cleanup"`, true, true},
	{"array-literal", `cleanup=('trap : EXIT'); eval "$cleanup"`, true, true},
	{"array-literal-of-several-words", `cleanup=('trap : EXIT' b); eval "$cleanup"`, true, true},
	{"declare-array-literal", `declare -a cleanup=('trap : EXIT'); eval "$cleanup"`, true, true},
	{"nameref-writes-its-target", `declare -n ref=cleanup; ref='trap : EXIT'; eval "$cleanup"`, true, true},
	{"nameref-writes-its-target-over-known", `cleanup='echo ok'; declare -n ref=cleanup; ref='trap : EXIT'; eval "$cleanup"`, true, true},
	{"nameref-reads-its-target", `declare -n ref=cleanup; cleanup='trap : EXIT'; eval "$ref"`, true, true},
	{"nameref-writes-its-target-after-reassign", `declare -n ref=cleanup; cleanup='echo ok'; ref='trap : EXIT'; eval "$cleanup"`, true, true},
	{"nameref-reads-its-target-after-reassign", `declare -n ref=cleanup; ref='echo ok'; cleanup='trap : EXIT'; eval "$ref"`, true, true},
	{"nameref-option-in-expansion", `opts=n; declare -$opts ref=cleanup; ref='trap : EXIT'; eval "$cleanup"`, true, true},
	{"nameref-target-given-later", `declare -n ref; ref=cleanup; ref='trap : EXIT'; eval "$cleanup"`, true, true},
	{"nameref-without-eval", `declare -n ref=out; ref=hi; echo "$out"`, false, false},
	{"export-quoted-equals", `export cleanup"=trap : EXIT"; eval "$cleanup"`, true, true},
	{"export-quoted-equals-over-known", `cleanup='echo ok'; export cleanup"=trap : EXIT"; eval "$cleanup"`, true, true},
	{"declare-quoted-assignment", `declare "cleanup=trap : EXIT"; eval "$cleanup"`, true, true},
	{"readonly-quoted-equals", `readonly cleanup"=trap : EXIT"; eval "$cleanup"`, true, true},
	{"export-name-in-expansion", `x=cleanup; export "$x=trap : EXIT"; eval "$cleanup"`, true, true},
	{"export-operand-in-expansion", `x='cleanup=trap : EXIT'; export "$x"; eval "$cleanup"`, true, true},
	{"export-operand-in-substitution", `export $(printf 'A=1'); echo "$A"`, true, false},
	{"export-of-plain-and-quoted-operands", `export PATH="$HOME/bin:$PATH"; export "GOFLAGS=-mod=readonly"; echo hi`, false, false},
	{"local-in-function", `f() { local x=1; echo "$x"; }; f`, false, false},
	{"function-evals-its-argument", `f() { eval "$1"; }; f 'trap : EXIT'`, true, true},
	{"positionals-set-then-evaluated", `set -- 'trap : EXIT'; eval "$1"`, true, true},
	{"positionals-set-then-run", `set -- trap : EXIT; "$@"`, true, true},
	{"positionals-set-then-first-run", `set -- trap : EXIT; $1 : EXIT`, true, true},
	{"positionals-run-without-set", `"$@"`, true, false},
	{"first-positional-before-command", `$1 echo hi`, true, false},
	{"function-runs-its-arguments-without-trap", `retry() { "$@"; }; retry echo hi`, false, false},

	{"install-one-liner", `sh -c 't=$(mktemp) && curl -sSfL -o "$t" https://raw.githubusercontent.com/kun9497/assay/0123456789abcdef0123456789abcdef01234567/install.sh && sh "$t" -b /usr/local/bin; s=$?; rm -f "$t"; exit $s'`, false, false},
	{"install-one-liner-with-sudo", `sh -c 't=$(mktemp) && curl -sSfL -o "$t" https://raw.githubusercontent.com/kun9497/assay/0123456789abcdef0123456789abcdef01234567/install.sh && sudo sh "$t" -b /usr/local/bin; s=$?; rm -f "$t"; exit $s'`, false, false},
}

// leakMisses are the shapes the guard's header lists as not read: Git Bash
// keeps an EXIT trap for every one and the guard accepts every one. They are
// held accepted so that the list is true of the reader: a rule that closes
// one turns its row red, and the row then moves to leakShapes and its line
// leaves the header.
var leakMisses = []struct{ name, script string }{
	{"multi-line-subshell-reassigns", "cleanup='trap \"echo LEAK\" EXIT'\n(\ncleanup='echo ok'\n)\neval \"$cleanup\""},
	{"heredoc-body-reassigns", "cleanup='trap \"echo LEAK\" EXIT'\ncat <<E >/dev/null\ncleanup='echo ok'\nE\neval \"$cleanup\""},
	{"trap-after-multi-line-string", "echo \"a\nb\"; trap 'echo LEAK' EXIT"},
	{"trap-handler-and-signal-in-one-expansion", `args=': EXIT'; trap $args`},
	{"unset-name-before-command", `$ASSAY_NO_SUCH_PREFIX trap 'echo LEAK' EXIT`},
	{"unknown-value-splits-before-slash", `x=$(printf 'trap : EXIT %s' x); $x/y`},
	{"function-runs-its-arguments", `f() { "$@"; }; f trap : EXIT`},
	{"function-runs-its-first-argument", `f() { $1 : EXIT; }; f trap`},
	{"mapfile-writes-name", `mapfile -t cleanup <<<'trap : EXIT'; eval "$cleanup"`},
	{"backtick-substitution-as-command-word", "`printf trap` 'echo LEAK' EXIT"},
	{"backtick-substitution-names-what-read-writes", "cleanup='echo ok'; read -r `printf cleanup` <<<'trap : EXIT'; eval \"$cleanup\""},
	{"backtick-substitution-names-what-export-writes", "cleanup='echo ok'; export `printf cleanup`='trap : EXIT'; eval \"$cleanup\""},
	{"alias", "shopt -s expand_aliases; alias c='trap : EXIT'\nc"},
}

func TestInstallLeakGuardDocumentedMisses(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range leakShapes {
		seen[tc.name] = true
	}
	for _, tc := range leakMisses {
		if seen[tc.name] {
			t.Fatalf("two rows are named %s", tc.name)
		}
		seen[tc.name] = true
		t.Run(tc.name, func(t *testing.T) {
			if got := firstShellLeak(tc.script); got != "" {
				t.Errorf("decoded run refused at %q a shape the header lists as not read: %s", got, tc.script)
			}
			if got := leakedInInstallJob(tc.script); got != "" {
				t.Errorf("install job refused at %q a shape the header lists as not read: %s", got, tc.script)
			}
		})
	}
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
