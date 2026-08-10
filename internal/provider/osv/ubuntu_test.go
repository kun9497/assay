package osv

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// TestUbuntuLineage pins which keys are mainline and which are not (D53).
//
// The negative rows are the point. OSV's schema documents only the bare :Pro:
// prefix, so every other spelling here is convention observed in the live export
// on 2026-08-10 — including the two shapes that do not follow the convention at
// all. A predicate written as a list of the six known families would store
// whatever family is invented next; written as "Ubuntu but not mainline", it
// cannot.
func TestUbuntuLineage(t *testing.T) {
	for _, tt := range []struct {
		eco  string
		want bool
	}{
		// Mainline: kept.
		{"Ubuntu:22.04:LTS", false},
		{"Ubuntu:24.04:LTS", false},
		{"Ubuntu:25.10", false},
		{"Ubuntu:14.04:LTS", false},
		// Lineage: dropped.
		{"Ubuntu:Pro:20.04:LTS", true},
		{"Ubuntu:Pro:FIPS:16.04:LTS", true},
		{"Ubuntu:Pro:FIPS-updates:18.04:LTS", true},
		{"Ubuntu:Pro:FIPS-preview:22.04:LTS", true},
		{"Ubuntu:Pro:Realtime:22.04:LTS", true},
		{"Ubuntu:Nvidia-BlueField:24.04:LTS", true},
		{"Ubuntu:22.04:LTS:for:NVIDIA:BlueField", true},
		{"Ubuntu:Pro:24.04:LTS:Realtime:Kernel", true},
		// The bare family name is not a key this project builds (D6), and a
		// malformed release is not one either. Both are dropped rather than
		// stored under a key nothing will ever look up.
		{"Ubuntu", true},
		{"Ubuntu:", true},
		{"Ubuntu:jammy", true},
		// Not Ubuntu at all: untouched, whichever ecosystem is being fetched.
		{"Debian:12", false},
		{"Alpine:v3.19", false},
		{"Go", false},
	} {
		if got := ubuntuLineage(tt.eco); got != tt.want {
			t.Errorf("ubuntuLineage(%q) = %v, want %v", tt.eco, got, tt.want)
		}
	}
}

// TestConvert_UbuntuLineageEntriesAreDropped is what makes the corpus
// affordable, and nothing else covers it: with the drop removed, every test in
// this package still passed.
//
// It also pins the property the drop's safety argument rests on — that a
// non-Ubuntu entry in the same record is untouched. What made stripping lossy
// once before was dropping entries another PASS had already indexed; the
// argument here is that no pass can index a lineage key, so only lineage
// entries may go.
func TestConvert_UbuntuLineageEntriesAreDropped(t *testing.T) {
	raw := map[string]any{
		"id":       "UBUNTU-CVE-2026-9999",
		"modified": "2026-08-10T00:00:00Z",
		"affected": []any{
			affectedJSON("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.15"),
			affectedJSON("Ubuntu:Pro:FIPS-updates:22.04:LTS", "openssl", "3.0.2-0ubuntu1.15+Fips1.2"),
			affectedJSON("Ubuntu:Pro:Realtime:22.04:LTS", "linux-realtime", "5.15.0-1042.45"),
			affectedJSON("Ubuntu:Nvidia-BlueField:22.04:LTS", "linux-bluefield", "5.15.0-1030.32"),
			// A neighbour from an ecosystem this build DOES index. It must
			// survive: dropping it is the exact regression the "every entry is
			// kept" comment in record.go was written for.
			affectedJSON("Debian:12", "openssl", "3.0.11-1~deb12u2"),
		},
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	adv, ok, err := Convert(data, "Ubuntu")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if !ok {
		t.Fatal("Convert returned ok=false; the record names a mainline Ubuntu key")
	}

	var got []string
	for _, a := range adv.Affected {
		got = append(got, a.Ecosystem)
	}
	want := []string{"Ubuntu:22.04:LTS", "Debian:12"}
	if len(got) != len(want) {
		t.Fatalf("kept %v, want %v — the three lineage entries must be dropped and "+
			"the Debian one must not be", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d is %q, want %q", i, got[i], want[i])
		}
	}

	// The mainline entry has to arrive intact, not merely present: a drop
	// implemented as "blank the ecosystem" would satisfy a count check.
	m := adv.Affected[0]
	if m.Name != "openssl" {
		t.Errorf("mainline entry name = %q, want openssl", m.Name)
	}
	if len(m.Ranges) != 1 || len(m.Ranges[0].Events) != 2 {
		t.Fatalf("mainline entry ranges = %+v, want one range with two events", m.Ranges)
	}
	if fixed := m.Ranges[0].Events[1].Fixed; fixed != "3.0.2-0ubuntu1.15" {
		t.Errorf("mainline fixed = %q, want 3.0.2-0ubuntu1.15 — the FIPS entry's "+
			"+Fips1.2 must not have leaked into it", fixed)
	}
}

// TestConvert_UbuntuLineageOnlyRecordYieldsNothing covers the record shape that
// exists only because lineages do: an advisory that names no mainline key at
// all. Every entry is dropped, so there is nothing to store, and Convert must
// say so rather than emitting a record with an empty Affected that the index
// would then point at.
func TestConvert_UbuntuLineageOnlyRecordYieldsNothing(t *testing.T) {
	raw := map[string]any{
		"id":       "UBUNTU-CVE-2026-8888",
		"modified": "2026-08-10T00:00:00Z",
		"affected": []any{
			affectedJSON("Ubuntu:Pro:FIPS-updates:18.04:LTS", "openssl", "1.1.1-1ubuntu2.1+Fips1"),
		},
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	adv, ok, err := Convert(data, "Ubuntu")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if ok {
		t.Errorf("Convert returned ok=true with Affected=%+v; a record naming only "+
			"lineage keys has nothing this build can store", adv.Affected)
	}
}

func affectedJSON(ecosystem, name, fixed string) map[string]any {
	return map[string]any{
		"package": map[string]any{"ecosystem": ecosystem, "name": name},
		"ranges": []any{map[string]any{
			"type": "ECOSYSTEM",
			"events": []any{
				map[string]any{"introduced": "0"},
				map[string]any{"fixed": fixed},
			},
		}},
	}
}

var _ = advisory.RangeEcosystem

// TestEcosystems_IncludesUbuntu pins the one-line list that decides whether any
// of the above ever runs against real data (D53).
//
// Dropping the entry does not break a scan loudly at build time — it makes
// `assay db build` stop fetching the archive, and an Ubuntu image then reports
// its ecosystem as absent from the database. That IS a loud skip and exit 2
// rather than a false clean, so this is a regression guard, not a safety one:
// without it, a mutation removing the entry left every test in the package
// green.
func TestEcosystems_IncludesUbuntu(t *testing.T) {
	for _, want := range []string{"Ubuntu", "Debian", "Alpine"} {
		if !slices.Contains(Ecosystems, want) {
			t.Errorf("Ecosystems = %v, want it to include %q", Ecosystems, want)
		}
	}
	// The lineage keys are archive CONTENTS, never archive paths: OSV serves
	// one Ubuntu/all.zip and the release- and lineage-qualified keys live
	// inside it (D6). Naming one here would request a path that does not
	// exist.
	for _, eco := range Ecosystems {
		if strings.Contains(eco, ":") {
			t.Errorf("Ecosystems contains %q; entries are archive paths, not keys", eco)
		}
	}
}
