package pkgmeta

import "testing"

func TestDebianPointRelease(t *testing.T) {
	for _, tc := range []struct{ content, versionID, want string }{
		{"12.11\n", "12", "12.11"},
		{"12.11", "12", "12.11"},
		{"  11.11\r\n", "11", "11.11"},
		{"trixie/sid\n", "", ""},
		{"trixie/sid\n", "13", ""},
		{"13.0\n", "12", ""}, // the two files disagree on the major
		{"12\n", "12", ""},   // no point release stated
		{"", "12", ""},
		{"12.11\n", "", "12.11"}, // no VERSION_ID to hold it to
	} {
		if got := DebianPointRelease(tc.content, tc.versionID); got != tc.want {
			t.Errorf("DebianPointRelease(%q, %q) = %q, want %q", tc.content, tc.versionID, got, tc.want)
		}
	}
}
