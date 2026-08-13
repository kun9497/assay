package tomlblock

import "testing"

// stringField is where a fabricated value would come from. Everything it
// refuses yields no field at all, which the callers then count as a skip -
// never a guess.

func TestStringField(t *testing.T) {
	cases := []struct {
		line string
		key  string
		want string
		ok   bool
	}{
		{`name = "serde"`, "name", "serde", true},
		{`version = "1.0.196"`, "version", "1.0.196", true},
		{`  name = "indented"`, "name", "indented", true},
		{`name="no-spaces"`, "name", "no-spaces", true},
		{`version = "1.0.0-alpha.1+build.5"`, "version", "1.0.0-alpha.1+build.5", true},
		// A different key entirely.
		{`source = "registry+https://x"`, "name", "", false},
		// A key the wanted one is a prefix of. Compared exactly, so this is
		// not a name.
		{`name_hint = "wrong"`, "name", "", false},
		// Not a quoted scalar: an array or an inline table.
		{`dependencies = [`, "dependencies", "", false},
		{`source = { registry = "x" }`, "source", "", false},
		{`name = ""`, "name", "", false},
		{`name`, "name", "", false},
	}

	for _, tc := range cases {
		got, ok := stringField(tc.line, tc.key)
		if got != tc.want || ok != tc.ok {
			t.Errorf("stringField(%q, %q) = %q, %v; want %q, %v", tc.line, tc.key, got, ok, tc.want, tc.ok)
		}
	}
}

// Assignments above the first [[package]] belong to no package at all.
//
// The fixture uses QUOTED values on purpose. A real preamble writes
// `version = 1` unquoted, which stringField refuses anyway — so a test built
// from a realistic preamble passes whether or not the open-block check exists,
// and cannot fail on its own subject. Quoted values are what make the two
// behaviours differ: without the check they accumulate into cur, and because
// opening a block does not clear cur, they then become the FIRST package's
// name and version while its own lines are ignored as second assignments.
func TestScan_PreambleIsNotPartOfTheFirstBlock(t *testing.T) {
	blocks := Scan([]byte(`version = "1"
name = "not-a-package"

[[package]]
name = "the-real-first"
version = "1.0.0"
`))

	if len(blocks) != 1 {
		t.Fatalf("blocks = %+v, want exactly one", blocks)
	}
	if blocks[0].Name != "the-real-first" || blocks[0].Version != "1.0.0" {
		t.Errorf("block = %+v, want the-real-first at 1.0.0", blocks[0])
	}
}

// Scan returns blocks in file order, and an incomplete one keeps its place
// rather than being dropped — the caller counts it, and a block that vanishes
// here is invisible to every counter downstream.
func TestScan_IncompleteBlockKeepsItsPlace(t *testing.T) {
	blocks := Scan([]byte(`[[package]]
name = "first"
version = "1.0.0"

[[package]]
name = "no-version"

[[package]]
name = "third"
version = "3.0.0"
`))

	if len(blocks) != 3 {
		t.Fatalf("blocks = %+v, want three", blocks)
	}
	if blocks[1].Name != "no-version" || blocks[1].Version != "" {
		t.Errorf("blocks[1] = %+v, want the incomplete block in the middle", blocks[1])
	}
	if blocks[2].Name != "third" {
		t.Errorf("blocks[2] = %+v, want third", blocks[2])
	}
}
