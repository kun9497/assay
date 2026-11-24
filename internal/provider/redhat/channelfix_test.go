package redhat

import (
	"sort"
	"strings"
	"testing"
)

// D175: which of a channel's builds join the mainline fixes, through convert.
// Shapes and builds are the documents' of 2026-11-24.
func TestConvert_D175_AChannelsRefixOfTheSameMinorIsKept(t *testing.T) {
	const main, eus = "cpe:/a:redhat:enterprise_linux:9::appstream", "cpe:/a:redhat:rhel_eus:9.8::appstream"
	for _, tc := range []struct {
		name, main, chanCPE, chanBuild, want string
	}{
		{"CVE-2026-93520 xorg", "0:1-34.el9_8.5 0:1-39.el9_9.1", eus, "0:1-34.el9_8.6", "0:1-34.el9_8.5 0:1-39.el9_9.1 0:1-34.el9_8.6"},
		{"E4S", "0:1-284.11.1.el9_2 0:1-570.35.1.el9_6", "cpe:/o:redhat:rhel_e4s:9.2::baseos", "0:1-284.134.1.el9_2", "0:1-284.11.1.el9_2 0:1-570.35.1.el9_6 0:1-284.134.1.el9_2"},
		{"RHEL 10's spelling", "0:1-4.el9_2.3 0:1-9.el9_3", "cpe:/o:redhat:enterprise_linux_eus:9.2", "0:1-4.el9_2.5", "0:1-4.el9_2.3 0:1-9.el9_3 0:1-4.el9_2.5"},
		{"at the other minor's fix", "0:1-4.el9_2 0:1-9.el9_3", eus, "0:1-9.el9_2", "0:1-4.el9_2 0:1-9.el9_3 0:1-9.el9_2"},
		{"the mainline's own build", "0:1-34.el9_8.5 0:1-39.el9_9.1", eus, "0:1-34.el9_8.5", "0:1-34.el9_8.5 0:1-39.el9_9.1"},
		{"below the mainline's", "0:1-34.el9_8.5 0:1-39.el9_9.1", eus, "0:1-34.el9_8.4", "0:1-34.el9_8.5 0:1-39.el9_9.1"},
		{"between the mainline's two", "0:1-34.el9_8.5 0:1-34.el9_8.9 0:1-39.el9_9.1", eus, "0:1-34.el9_8.7", "0:1-34.el9_8.5 0:1-34.el9_8.9 0:1-39.el9_9.1"},
		{"a minor the mainline did not fix", "0:1-34.el9_8.5 0:1-39.el9_9.1", eus, "0:1-34.el9_6.8", "0:1-34.el9_8.5 0:1-39.el9_9.1"},
		{"above every other minor's", "0:1-34.el9_8.5 0:1-34.el9_7.9", eus, "0:1-34.el9_8.6", "0:1-34.el9_7.9 0:1-34.el9_8.5"},
		{"the one minor there is", "0:1-34.el9_8.5", eus, "0:1-34.el9_8.6", "0:1-34.el9_8.5"},
		{"no minor", "0:1-34.el9 0:1-39.el9_9.1", eus, "0:1-35.el9", "0:1-34.el9 0:1-39.el9_9.1"},
		{"another major", "0:1-34.el9_8.5 0:1-39.el9_9.1", "cpe:/a:redhat:rhel_eus:8.8::appstream", "0:1-34.el9_8.6", "0:1-34.el9_8.5 0:1-39.el9_9.1"},
		{"another product", "0:1-34.el9_8.5 0:1-39.el9_9.1", "cpe:/a:redhat:openstack:9::el9", "0:1-34.el9_8.6", "0:1-34.el9_8.5 0:1-39.el9_9.1"},
		{"a module's", "0:1-34.el9_8.5 0:1-39.el9_9.1", eus, "0:1-34.el9_8.6.x86_64::m:1", "0:1-34.el9_8.5 0:1-39.el9_9.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ids := []string{"C:x-" + strings.Replace(tc.chanBuild+".x86_64", ".x86_64::m:1.x86_64", ".x86_64::m:1", 1)}
			for _, m := range strings.Fields(tc.main) {
				ids = append(ids, "M:x-"+m+".x86_64", "M:x-"+m+".src")
			}
			var st stats
			adv, ok := convert(buildDoc(t, "CVE-2026-93520", map[string]string{"M": main, "C": tc.chanCPE}, ids, nil), &st)
			if !ok || len(adv.Affected) != 1 {
				t.Fatalf("convert: %v, %+v", ok, adv.Affected)
			}
			var got []string
			for _, r := range adv.Affected[0].Ranges {
				got = append(got, r.Events[1].Fixed)
			}
			want := strings.Fields(tc.want)
			if n := len(want) - len(strings.Fields(tc.main)); st.ChannelRefixes != n {
				t.Errorf("ChannelRefixes = %d, want %d", st.ChannelRefixes, n)
			}
			sort.Strings(got)
			sort.Strings(want)
			if strings.Join(got, " ") != strings.Join(want, " ") {
				t.Errorf("fixes %v, want %v", got, want)
			}
		})
	}
	// A channel build alone makes no entry (D47).
	var st stats
	if adv, ok := convert(buildDoc(t, "CVE-2026-1", map[string]string{"C": eus}, []string{"C:x-0:1-34.el9_8.6.x86_64"}, nil), &st); ok {
		t.Errorf("a channel's build alone was stored: %+v", adv.Affected)
	}
	if s := (stats{SkippedELSFixed: 3, ChannelRefixes: 7}).String(); !strings.Contains(s, "3 fixed builds on an ELS channel (D47), 7 channel builds kept as a mainline minor's second fix (D175)") {
		t.Error(s)
	}
}
