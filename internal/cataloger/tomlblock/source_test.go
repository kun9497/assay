package tomlblock

import "testing"

func TestScan_Source(t *testing.T) {
	blocks := Scan([]byte(`[[package]]
name = "cargo-git"
version = "1.0.0"
source = "git+https://github.com/someone/cargo-git#0123"

[[package]]
name = "uv-inline"
version = "2.0.0"
source = { git = "https://github.com/someone/uv-inline?rev=main#0123" }
dependencies = [
    { name = "dep", source = { registry = "https://pypi.org/simple" } },
]

[[package]]
name = "no-source"
version = "3.0.0"
dependencies = [
    { name = "dep", source = { registry = "https://pypi.org/simple" } },
]
`))
	want := []Block{
		{Name: "cargo-git", Version: "1.0.0", Source: "git+https://github.com/someone/cargo-git#0123"},
		{Name: "uv-inline", Version: "2.0.0", Source: `{ git = "https://github.com/someone/uv-inline?rev=main#0123" }`},
		// A dependency's inline source is not this block's.
		{Name: "no-source", Version: "3.0.0"},
	}
	if len(blocks) != len(want) {
		t.Fatalf("blocks = %+v, want %+v", blocks, want)
	}
	for i := range want {
		if blocks[i] != want[i] {
			t.Errorf("block %d = %+v, want %+v", i, blocks[i], want[i])
		}
	}
}

func TestRawField(t *testing.T) {
	cases := []struct {
		line, want string
		ok         bool
	}{
		{`source = "registry+https://x"`, "registry+https://x", true},
		{`source = { editable = "." }`, `{ editable = "." }`, true},
		{`source_hint = "x"`, "", false},
		{`source =`, "", false},
		{`{ name = "x", source = { git = "y" } },`, "", false},
	}
	for _, tc := range cases {
		got, ok := rawField(tc.line, "source")
		if got != tc.want || ok != tc.ok {
			t.Errorf("rawField(%q) = %q, %v; want %q, %v", tc.line, got, ok, tc.want, tc.ok)
		}
	}
}
