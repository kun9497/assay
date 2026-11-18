package scancmd

import (
	"fmt"
	"testing"
)

// A bare listing can legitimately join an architecture-specific installation
// of the same unsupported or contradictory OS. Its source version must stay
// in that group, even when an independently keyed installation shares the
// binary's name, version and architecture.
func TestRun_CDXPooledSourceCannotCrossOSEvidence(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("conflict=%t/reverse=%t", conflict, reverse), func(t *testing.T) {
				db := vexDB(t, "Debian:12", vexAdv{"QA-12", "CVE-2031-9110", "apt", "3.0.4"})
				osInfo, qualifier := "", "&distro=debian-sid"
				if conflict {
					osInfo = `{"type":"operating-system","name":"debian","version":"12","properties":[{"name":"syft:distro:versionID","value":"11"}]},`
					qualifier = ""
				}
				known := `{"type":"library","purl":"pkg:deb/debian/apt@3.0.3?arch=amd64&distro=debian-12"}`
				unknown := `{"type":"library","purl":"pkg:deb/debian/apt@3.0.3?arch=amd64` + qualifier + `"}`
				bare := `{"type":"library","purl":"pkg:deb/debian/apt@3.0.3?upstream=apt%403.0.5` + qualifier + `"}`
				list := known + "," + unknown
				if reverse {
					list = unknown + "," + known
				}
				rep, rc := scanOSRegression(t, db, `{"bomFormat":"CycloneDX","components":[`+osInfo+list+`],"metadata":{"component":`+bare+`}}`)
				wantExit, wantTarget := 1, 0
				if conflict {
					wantExit, wantTarget = 2, 1
				}
				if rc != wantExit || rep.Summary.Components != 2 || rep.Summary.Evaluated != 1 || rep.Summary.TargetIncomplete != wantTarget || len(rep.Findings) != 1 || len(rep.Skipped) != 1 {
					t.Fatalf("exit %d, summary %+v, findings %+v, skips %+v", rc, rep.Summary, rep.Findings, rep.Skipped)
				}
			})
		}
	}
}
