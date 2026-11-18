package ciguard

import "testing"

func TestInstallLeakGuardConditionalValuesAndEval(t *testing.T) {
	for _, script := range []string{
		`cleanup='trap "echo cleanup" EXIT'; false && cleanup='echo ok'; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; true || cleanup='echo ok'; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; if false; then cleanup='echo ok'; fi; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; if false; then :; cleanup='echo ok'; fi; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; if true; then :; else cleanup='echo ok'; fi; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; if true; then :; elif cleanup='echo ok'; then :; fi; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; while false; do cleanup='echo ok'; done; eval "$cleanup"`,
		"cleanup='trap \"echo cleanup\" EXIT'\nif false; then\n  cleanup='echo ok'\nfi\neval \"$cleanup\"",
		`cleanup='trap "echo cleanup" EXIT'; false && unset cleanup; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; if false; then unset cleanup; fi; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; unset -f cleanup; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; false && export cleanup='echo ok'; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; false && eval "cleanup='echo ok'"; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; false && { :; cleanup='echo ok'; }; eval "$cleanup"`,
		"cleanup='trap \"echo cleanup\" EXIT'; false &&\ncleanup='echo ok'; eval \"$cleanup\"",
		`cleanup='trap "echo cleanup" EXIT'; eval "$cleanup;"`,
		`cleanup='trap "echo cleanup" EXIT'; eval "true; $cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; eval " $cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; eval -- "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; eval "${cleanup:-}"`,
		`cleanup='trap "echo cleanup" EXIT'; cleanup="$other"; eval "$cleanup"`,
		`sig=EXIT; trap 'echo cleanup' $sig`,
		// These remain conservative refusals: braces are not tracked and
		// the last pipeline stage can run in the parent with bash lastpipe.
		`{ trap 'echo cleanup' EXIT; } | cat`,
		"true |\ntrap 'echo cleanup' EXIT",
		`true | trap 'echo cleanup' EXIT`,
		`true | cleanup='trap "echo cleanup" EXIT'; eval "$cleanup"`,
	} {
		t.Run(script, func(t *testing.T) {
			if got := firstShellLeak(script); got == "" {
				t.Error("decoded install run accepted a possible parent-shell trap")
			}
			if got := leakedInInstallJob(script); got == "" {
				t.Error("install-job document accepted a possible parent-shell trap")
			}
		})
	}
	for _, script := range []string{
		`cleanup='trap "echo cleanup" EXIT'; cleanup='echo ok'; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; unset cleanup; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; false && cleanup='echo ok'; cleanup='echo fine'; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; false && cleanup='echo ok'; unset cleanup; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; if false; then cleanup='echo ok'; fi; cleanup='echo safe'; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; false && { :; cleanup='echo ok'; }; cleanup='echo safe'; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; unset -v cleanup; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; unset -- cleanup; eval "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; printf '%s' "$cleanup"`,
		`cleanup='trap "echo cleanup" EXIT'; sh -c "$cleanup"`,
		`cleanup='trap "echo cleanup" TERM'; eval -- "$cleanup"`,
		`sig=EXIT; trap - $sig`,
	} {
		if got := firstShellLeak(script); got != "" {
			t.Errorf("safe install run refused at %q: %s", got, script)
		}
	}
}
