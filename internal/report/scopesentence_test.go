package report

import "testing"

// ApplicationScopeSentence's arms the one production record never exercises:
// nil, a single entry on a side, and no roots. The Run-level D160 tests hold
// the production wording; this holds the builder's edges so a mutation of
// joinAnd's one-element arm or the nil guard is not a survivor.
func TestApplicationScopeSentence_Edges(t *testing.T) {
	if r, n := ApplicationScopeSentence(nil); r != "" || n != "" {
		t.Errorf("nil record = %q / %q, want empty", r, n)
	}
	for _, tc := range []struct {
		name        string
		scope       []ApplicationScopeRecord
		read, notRd string
	}{
		{"nothing", nil, "", ""},
		{"one read, no roots", []ApplicationScopeRecord{{Ecosystem: "npm", State: ScopeRead}}, "npm packages", ""},
		{"one none with one root", []ApplicationScopeRecord{{Ecosystem: "Go", State: ScopeNone, Roots: []string{"usr/bin"}}}, "Go binaries directly in usr/bin", ""},
		{"two roots", []ApplicationScopeRecord{{Ecosystem: "npm", State: ScopeRead, Roots: []string{"a", "b"}}}, "npm packages under a and b", ""},
		{"one not-read", []ApplicationScopeRecord{{Ecosystem: "PyPI", State: ScopeNotRead}}, "", "Python packages"},
		{"two not-read", []ApplicationScopeRecord{{Ecosystem: "PyPI", State: ScopeNotRead}, {Ecosystem: "Maven", State: ScopeNotRead}}, "", "Python packages and Java packages"},
		{"unknown ecosystem keeps its key", []ApplicationScopeRecord{{Ecosystem: "RubyGems", State: ScopeNotRead}}, "", "RubyGems packages"},
	} {
		r, n := ApplicationScopeSentence(&InventoryScopeRecord{ApplicationScope: tc.scope})
		if r != tc.read || n != tc.notRd {
			t.Errorf("%s: = %q / %q, want %q / %q", tc.name, r, n, tc.read, tc.notRd)
		}
	}
}
