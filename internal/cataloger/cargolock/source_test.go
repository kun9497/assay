package cargolock

import "testing"

func TestParse_GitSourceIsRefused(t *testing.T) {
	path := write(t, `version = 3

[[package]]
name = "workspace-root"
version = "0.1.0"

[[package]]
name = "kept-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "sparse-crate"
version = "2.0.0"
source = "sparse+https://index.crates.io/"

[[package]]
name = "forked-crate"
version = "0.10.40"
source = "git+https://github.com/someone/forked-crate?branch=main#0123"
`)
	pkgs, stats, skipped, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	// The unsourced workspace crate stays cataloged, as before: counting it
	// would make every healthy Cargo scan incomplete.
	want := map[string]string{"workspace-root": "0.1.0", "kept-crate": "1.0.0", "sparse-crate": "2.0.0"}
	if len(got) != len(want) {
		t.Fatalf("packages = %v, want %v", got, want)
	}
	for n, v := range want {
		if got[n] != v {
			t.Errorf("%s = %q, want %q", n, got[n], v)
		}
	}
	if stats.Components != 4 || stats.Cataloged != 3 || stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %+v, want 4 components, 3 cataloged, 1 SkippedNoVersion", stats)
	}
	if len(skipped) != 1 || skipped[0].Name != "forked-crate" || skipped[0].Reason == "" {
		t.Errorf("skipped = %+v, want forked-crate named with a reason", skipped)
	}
}
