package gobinary

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// D160: the image probe hands a binary's bytes, not a path. ParseBytes must
// yield exactly what Parse yields for the same binary, located at the path
// the caller names (the binary's path inside the image).
func TestParseBytes_MatchesParseAndLocatesAtTheGivenPath(t *testing.T) {
	bin := buildFixtureNoVCS(t,
		"module example.test/app\n\ngo 1.26\n\nrequire go.etcd.io/bbolt v1.5.0\n",
		"package main\n\nimport _ \"go.etcd.io/bbolt\"\n\nfunc main() {}\n")
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	fromPath, statsPath, err := Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	fromBytes, statsBytes, err := ParseBytes(data, "usr/bin/tool")
	if err != nil {
		t.Fatal(err)
	}
	// The one difference: the unstamped "(devel)" main module is a counted
	// skip for a file: target and not a component for an in-image probe.
	if statsPath.SkippedNoVersion != 1 || statsBytes.SkippedNoVersion != 0 ||
		statsBytes.Components != statsPath.Components-1 || statsBytes.Cataloged != statsPath.Cataloged {
		t.Errorf("stats: bytes %+v, path %+v -- want the probe's to drop exactly the unversioned main module's skip", statsBytes, statsPath)
	}
	if len(fromBytes.Packages) != len(fromPath.Packages) || len(fromBytes.Packages) == 0 {
		t.Fatalf("ParseBytes yielded %d packages, Parse %d", len(fromBytes.Packages), len(fromPath.Packages))
	}
	for i := range fromBytes.Packages {
		b, p := fromBytes.Packages[i], fromPath.Packages[i]
		if len(b.Locations) != 1 || b.Locations[0].Path != "usr/bin/tool" {
			t.Errorf("package %s located at %+v, want usr/bin/tool", b.Name, b.Locations)
		}
		b.Locations, p.Locations = nil, nil
		if !reflect.DeepEqual(b, p) {
			t.Errorf("package %d differs:\n bytes: %+v\n path:  %+v", i, b, p)
		}
	}
	if find(t, fromBytes, "go.etcd.io/bbolt").Version != "v1.5.0" {
		t.Error("the linked dependency did not come through ParseBytes")
	}
}

// Bytes that are not a Go binary are an error naming the path, so the image
// probe can skip them silently while a direct caller still learns which file.
func TestParseBytes_RejectsNonGoBytesNamingThePath(t *testing.T) {
	_, _, err := ParseBytes([]byte("\x7fELF not really an elf file at all"), "usr/bin/cprogram")
	if err == nil || !strings.Contains(err.Error(), "usr/bin/cprogram") {
		t.Errorf("err = %v, want an error naming usr/bin/cprogram", err)
	}
}
