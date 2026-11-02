package uvlock

import "testing"

func TestParse_SourceKinds(t *testing.T) {
	rows := []struct {
		source  string
		kept    bool // cataloged
		counted bool // when not kept: SkippedNoVersion, else shown only
	}{
		{`{ registry = "https://pypi.org/simple" }`, true, false},
		{`{ registry = "https://pypi.internal.example/simple" }`, true, false},
		// The project itself when it is not a package: cataloged as before.
		{`{ virtual = "." }`, true, false},
		{`{ git = "https://github.com/someone/sourced-dist?rev=main#0123" }`, false, true},
		{`{ url = "https://example.invalid/sourced_dist-3.2.0.tar.gz" }`, false, true},
		{`{ path = "../vendor/sourced_dist-3.2.0.tar.gz" }`, false, true},
		{`{ directory = "../sourced-dist" }`, false, true},
		{`{ editable = "." }`, false, false},
	}
	for _, r := range rows {
		t.Run(r.source, func(t *testing.T) {
			path := write(t, `version = 1

[[package]]
name = "kept-dist"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "sourced-dist"
version = "3.2.0"
source = `+r.source+`
`)
			pkgs, stats, skipped, err := Parse(path)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if r.kept {
				if len(pkgs) != 2 || stats.Components != 2 || stats.Cataloged != 2 || len(skipped) != 0 {
					t.Errorf("packages = %+v, stats = %+v, skipped = %+v; want both cataloged", pkgs, stats, skipped)
				}
				return
			}
			if len(pkgs) != 1 || pkgs[0].Name != "kept-dist" {
				t.Errorf("packages = %+v, want kept-dist alone", pkgs)
			}
			wantComponents, wantSkipped := 1, 0
			if r.counted {
				wantComponents, wantSkipped = 2, 1
			}
			if stats.Components != wantComponents || stats.Cataloged != 1 || stats.SkippedNoVersion != wantSkipped {
				t.Errorf("stats = %+v, want %d components, 1 cataloged, %d SkippedNoVersion",
					stats, wantComponents, wantSkipped)
			}
			if len(skipped) != 1 || skipped[0].Name != "sourced-dist" || skipped[0].Reason == "" {
				t.Errorf("skipped = %+v, want sourced-dist named with a reason", skipped)
			}
		})
	}
}

func TestSourceKey(t *testing.T) {
	cases := map[string]string{
		`{ git = "https://x?rev=a#b" }`: "git",
		`{editable="."}`:                "editable",
		`"registry+https://x"`:          "",
		``:                              "",
		`{ }`:                           "",
	}
	for in, want := range cases {
		if got := sourceKey(in); got != want {
			t.Errorf("sourceKey(%q) = %q, want %q", in, got, want)
		}
	}
}
