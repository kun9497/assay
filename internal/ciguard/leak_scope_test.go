package ciguard

import "testing"

func TestInstallLeakGuardShellScopes(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		unsafe       bool
	}{
		{"pipeline-group-unset", `cleanup='trap "echo cleanup" EXIT'; { unset cleanup; } | cat; eval "$cleanup"`, true},
		{"pipeline-group-reassign", `cleanup='trap "echo cleanup" EXIT'; { cleanup='echo safe'; } | cat; eval "$cleanup"`, true},
		{"async-group-reassign", `cleanup='trap "echo cleanup" EXIT'; { cleanup='echo safe'; } & wait; eval "$cleanup"`, true},
		{"indirect-eval", `cleanup='trap "echo cleanup" EXIT'; variable=cleanup; eval "${!variable}"`, true},
		{"dead-eval-unbalanced", `cleanup='trap "echo cleanup" EXIT'; false && eval 'fi; cleanup="echo safe"'; eval "$cleanup"`, true},
		{"special-builtin-prefix", `cleanup='echo safe'; cleanup='trap "echo cleanup" EXIT' :; eval "$cleanup"`, true},
		{"special-export-prefix", `cleanup='echo safe'; cleanup='trap "echo cleanup" EXIT' export PATH; eval "$cleanup"`, true},
		{"special-eval-prefix", `cleanup='echo safe'; cleanup='trap "echo cleanup" EXIT' eval 'eval "$cleanup"'`, true},
		// eval's grammar cannot close a block in the calling shell, and a
		// string in a skipped branch must not erase the branch's uncertainty.
		{"eval-cannot-close-parent", `cleanup='trap "echo cleanup" EXIT'; if false; then eval 'fi'; cleanup='echo safe'; fi; eval "$cleanup"`, true},
		{"malformed-eval-refused", `cleanup='trap "echo cleanup" EXIT'; eval 'fi; cleanup="echo safe"' || :; eval "$cleanup"`, true},
		{"unclosed-eval-refused", `cleanup='trap "echo cleanup" EXIT'; eval 'if false; then cleanup="echo safe"'; eval "$cleanup"`, true},
		{"mismatched-eval-close-refused", `cleanup='trap "echo cleanup" EXIT'; eval 'if true; then :; done; cleanup="echo safe"' || :; eval "$cleanup"`, true},
		{"mismatched-eval-brace-refused", `cleanup='trap "echo cleanup" EXIT'; eval '{ if true; then :; }; fi; cleanup="echo safe"' || :; eval "$cleanup"`, true},
		{"direct-brace-unset", `cleanup='trap "echo cleanup" EXIT'; { unset cleanup; }; eval "$cleanup"`, false},
		{"direct-brace-reassign", `cleanup='trap "echo cleanup" EXIT'; { cleanup='echo safe'; }; eval "$cleanup"`, false},
		{"eval-assignment-persists", `cleanup='trap "echo cleanup" EXIT'; eval 'cleanup="echo safe"'; eval "$cleanup"`, false},
		{"eval-block-is-balanced", `cleanup='trap "echo cleanup" EXIT'; eval 'if true; then :; fi; cleanup="echo safe"'; eval "$cleanup"`, false},
		{"eval-nested-block-is-balanced", `cleanup='trap "echo cleanup" EXIT'; eval '{ while false; do :; done; }; cleanup="echo safe"'; eval "$cleanup"`, false},
		{"eval-for-is-balanced", `cleanup='trap "echo cleanup" EXIT'; eval 'for item in x; do :; done; cleanup="echo safe"'; eval "$cleanup"`, false},
		{"ordinary-command-prefix", `cleanup='echo safe'; cleanup='trap "echo cleanup" EXIT' true; eval "$cleanup"`, false},
		{"indirect-text-is-not-eval", `cleanup='trap "echo cleanup" EXIT'; variable=cleanup; printf '%s' "${!variable}"`, false},
		{"quoted-brace-is-not-a-group", `printf '%s' '}' | cat`, false},
		{"background-assignment-is-isolated", `cleanup='trap "echo cleanup" EXIT' & wait; eval "$cleanup"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstShellLeak(tc.script) != ""; got != tc.unsafe {
				t.Errorf("decoded run rejected=%v, want %v: %s", got, tc.unsafe, tc.script)
			}
			if got := leakedInInstallJob(tc.script) != ""; got != tc.unsafe {
				t.Errorf("install job rejected=%v, want %v: %s", got, tc.unsafe, tc.script)
			}
		})
	}
}
