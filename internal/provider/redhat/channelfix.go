package redhat

import (
	"regexp"
	"strings"

	"github.com/kun9497/assay/internal/version"
)

// channelCPE matches a support channel of RHEL (EUS, E4S, AUS, TUS, ELS), whose
// fixed builds D47 does not key to the major.
var channelCPE = regexp.MustCompile(`^cpe:/[oa]:redhat:(?:rhel_[a-z0-9_]+|enterprise_linux_eus):(\d+)(?:\.\d+)?(?:::.*)?$`)

// channelFix reads a fixed build a support channel shipped, when its release
// names a RHEL minor.
func channelFix(id string, cpe map[string]string) (productKey, string, bool) {
	plat, comp, _ := strings.Cut(id, ":")
	m := channelCPE.FindStringSubmatch(cpe[plat])
	if m == nil {
		return productKey{}, "", false
	}
	comp, context := splitContext(comp)
	name, evr := splitNEVRA(stripArch(comp))
	if context != "" || version.RHELMinor(evr) == "" {
		return productKey{}, "", false
	}
	return productKey{eco: "Red Hat:" + m[1], pkg: name}, evr, true
}

// refixes returns the channel's builds that fix again what the mainline fixed
// in the same minor (D175). CVE-2026-93520 is xorg-x11-server 34.el9_8.5 on
// mainline 9.8 and, three weeks later, 34.el9_8.6 on 9.8 EUS: judged by its own
// minor's fix, 34.el9_8.5 would be clean of what Red Hat found it still has.
//
// Only where another minor's mainline fix is above the build, which is
// where the matcher's own-minor rule takes that fix away. [0, build) is then
// inside a window the record already holds, so no build is reported that was
// not before the rule, and a channel's builds are still not keyed otherwise.
func refixes(mainline, channel map[string]bool) []string {
	cmp := version.RPM{}
	var out []string
next:
	for _, c := range sortedKeys(channel) {
		above, covered := false, false
		for _, m := range sortedKeys(mainline) {
			d, err := cmp.Compare(m, c)
			if err != nil {
				continue
			}
			if version.RHELMinor(m) != version.RHELMinor(c) {
				covered = covered || d > 0
				continue
			}
			if d >= 0 {
				continue next
			}
			above = true
		}
		if above && covered {
			out = append(out, c)
		}
	}
	return out
}
