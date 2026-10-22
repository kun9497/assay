package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/dbcmd"
)

// --allow-unsigned (D137) is accepted in any position after `update`, with
// or without --from, and is never implied: --from alone pulls from a mirror
// and still verifies, because a mirror is exactly where a stripped
// signature would come from. Driven against resolveUpdateRef directly for
// the reason TestResolveUpdateRef gives: the success path must not reach
// dbcmd.Pull with the real default ref.
func TestResolveUpdateRef_AllowUnsigned(t *testing.T) {
	def := dbcmd.Ref(dbcmd.DefaultRef)
	cases := []struct {
		name      string
		args      []string
		wantRef   string
		wantAllow bool
	}{
		{"flag alone", []string{"db", "update", "--allow-unsigned"}, def, true},
		{"after --from", []string{"db", "update", "--from", "example.test/mirror:v6", "--allow-unsigned"}, "example.test/mirror:v6", true},
		{"before --from", []string{"db", "update", "--allow-unsigned", "--from", "example.test/mirror:v6"}, "example.test/mirror:v6", true},
		{"--from alone does not imply it", []string{"db", "update", "--from", "example.test/mirror:v6"}, "example.test/mirror:v6", false},
		{"nothing does not imply it", []string{"db", "update"}, def, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stderr bytes.Buffer
			ref, allow, ok := resolveUpdateRef(c.args, &stderr)
			if !ok {
				t.Fatalf("ok = false, want true (stderr: %s)", stderr.String())
			}
			if ref != c.wantRef {
				t.Errorf("ref = %q, want %q", ref, c.wantRef)
			}
			if allow != c.wantAllow {
				t.Errorf("allowUnsigned = %v, want %v", allow, c.wantAllow)
			}
		})
	}

	t.Run("a flag that is not one of the two is still rejected", func(t *testing.T) {
		var stderr bytes.Buffer
		if _, _, ok := resolveUpdateRef([]string{"db", "update", "--allow-unsigned", "--allow-anything"}, &stderr); ok {
			t.Error("ok = true, want false")
		}
		if !strings.Contains(stderr.String(), `unknown db update flag "--allow-anything"`) {
			t.Errorf("stderr does not name the unrecognized flag:\n%s", stderr.String())
		}
	})
	t.Run("--from still needs its value when the other flag follows", func(t *testing.T) {
		var stderr bytes.Buffer
		if _, _, ok := resolveUpdateRef([]string{"db", "update", "--from", "--allow-unsigned"}, &stderr); ok {
			t.Error("ok = true, want false: --from swallowed the next flag as its reference")
		}
	})
}
