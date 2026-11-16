package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/store"
)

// Main QA of 4d823d1 (2026-11-16), through Run: an SBOM naming Debian as
// slink or potato spells them (2.1r5, 2.2r7) beside one npm package is held
// to --fail-on-eol -- EOL 2000-10-30 / 2003-06-30, exit 1 -- as 2.1 and 2.2
// are; the spelling keys nothing (the OS has no advisory key) and is no VEX
// alias. Lenny's 5.0r10, no Debian spelling, stays unknown.
func TestRun_EOLGateReachesSlinkAndPotatoRevisions(t *testing.T) {
	db := testDBWithEOL(t, []store.EOLRelease{
		{DistroID: "debian", Release: "2.1", EOLFrom: "2000-10-30", EOLLabel: "Debian LTS"},
		{DistroID: "debian", Release: "2.2", EOLFrom: "2003-06-30", EOLLabel: "Debian LTS"},
		{DistroID: "debian", Release: "5", EOLFrom: "2012-02-06", EOLLabel: "Debian LTS"},
	})
	pinClock(t, time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC))
	for _, tc := range []struct {
		version, eolFrom string
		code             int
	}{
		{"2.1r5", "2000-10-30", 1},
		{"2.2r7", "2003-06-30", 1},
		{"2.1", "2000-10-30", 1},
		{"5.0r10", "", 0},
	} {
		t.Run(tc.version, func(t *testing.T) {
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` +
				`{"type":"operating-system","name":"debian","version":"` + tc.version + `","properties":[{"name":"syft:distro:id","value":"debian"},{"name":"syft:distro:versionID","value":"` + tc.version + `"}]},` +
				`{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}`
			p := filepath.Join(t.TempDir(), "sbom.cdx.json")
			if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnEOL: true}, &out, &errOut)
			var rep report.Document
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatalf("stdout is not one JSON document: %v\nstderr: %s", err, errOut.String())
			}
			got := ""
			if rep.EOL != nil {
				got = rep.EOL.EOLFrom
			}
			if code != tc.code || got != tc.eolFrom || rep.Summary.Evaluated != 1 {
				t.Fatalf("exit %d, eolFrom %q, evaluated %d; want exit %d, eolFrom %q, evaluated 1\nstderr: %s",
					code, got, rep.Summary.Evaluated, tc.code, tc.eolFrom, errOut.String())
			}
			if tc.eolFrom == "" && !strings.Contains(errOut.String(), "EOL unknown") {
				t.Errorf("no EOL unknown warning\nstderr: %s", errOut.String())
			}
		})
	}
	// The spelling is still no advisory key and no VEX alias.
	for _, v := range []string{"2.1r5", "2.2r7"} {
		if key, err := (pkgmeta.Distro{ID: "debian", VersionID: v}).Ecosystem(); err == nil {
			t.Errorf("Debian %s keyed %q; want no key", v, key)
		}
		if got := pkgmeta.CanonicalDistroQualifier("debian-" + v); got != "debian-"+v {
			t.Errorf("debian-%s canonicalised to %q; want it compared as written", v, got)
		}
	}
}
