package version

import "regexp"

var rhelMinor = regexp.MustCompile(`\.(el[0-9]+_[0-9]+)`)

// RHELMinor is the RHEL minor a z-stream build's dist tag names: "el10_2" in
// 8.12.1-4.el10_2.7. A build of no particular minor carries a bare ".el10",
// and a module build's "+el8.5.0+" is not this; both are "".
func RHELMinor(evr string) string {
	if m := rhelMinor.FindStringSubmatch(evr); m != nil {
		return m[1]
	}
	return ""
}
