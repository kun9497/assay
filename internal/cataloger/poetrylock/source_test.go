package poetrylock

import "testing"

func TestParse_NonRegistrySourceTypes(t *testing.T) {
	rows := []struct {
		typ     string
		refused bool
	}{
		{"git", true},
		{"url", true},
		{"file", true},
		{"directory", true},
		// Named package indexes are still registry releases.
		{"legacy", false},
		{"supplemental", false},
		{"explicit", false},
	}
	for _, r := range rows {
		t.Run(r.typ, func(t *testing.T) {
			// [package.dependencies] sits between the package's keys and its
			// [package.source], as poetry writes it: the block must stay
			// pending across it.
			p := write(t, `[[package]]
name = "kept-dist"
version = "1.0.0"

[[package]]
name = "sourced-dist"
version = "3.2.0"

[package.dependencies]
asgiref = ">=3.3.2"

[package.source]
type = "`+r.typ+`"
url = "https://example.invalid/x"
reference = "main"

[[package]]
name = "after-dist"
version = "5.0.0"

[metadata]
lock-version = "2.0"
`)
			pkgs, stats, skipped, err := Parse(p)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got := map[string]bool{}
			for _, pk := range pkgs {
				got[pk.Name] = true
			}
			if !got["kept-dist"] || !got["after-dist"] {
				t.Errorf("packages = %+v, want kept-dist and after-dist", pkgs)
			}
			if stats.Components != 3 {
				t.Errorf("Components = %d, want 3", stats.Components)
			}
			if r.refused {
				if got["sourced-dist"] || stats.Cataloged != 2 || stats.SkippedNoVersion != 1 {
					t.Errorf("packages = %+v, stats = %+v; want sourced-dist refused and counted", pkgs, stats)
				}
				if len(skipped) != 1 || skipped[0].Name != "sourced-dist" || skipped[0].Reason == "" {
					t.Errorf("skipped = %+v, want sourced-dist named with a reason", skipped)
				}
				return
			}
			if !got["sourced-dist"] || stats.Cataloged != 3 || stats.SkippedNoVersion != 0 || len(skipped) != 0 {
				t.Errorf("packages = %+v, stats = %+v, skipped = %+v; want sourced-dist cataloged",
					pkgs, stats, skipped)
			}
		})
	}
}

// The source type belongs to its own block: the next [[package]] must start
// with none, or a registry package after a git one would be refused too.
func TestParse_SourceTypeDoesNotLeakIntoTheNextBlock(t *testing.T) {
	p := write(t, `[[package]]
name = "sourced-dist"
version = "3.2.0"

[package.source]
type = "git"
url = "https://example.invalid/x.git"

[[package]]
name = "next-dist"
version = "1.0.0"
`)
	pkgs, _, _, err := Parse(p)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "next-dist" {
		t.Errorf("packages = %+v, want next-dist alone", pkgs)
	}
}
