package pkgmeta

import "testing"

func TestUbuntuCodename(t *testing.T) {
	for q, want := range map[string]string{
		"jammy":        "jammy",
		"JAMMY":        "jammy",
		"ubuntu-jammy": "jammy",
		"Ubuntu-Jammy": "jammy",
		"noble":        "noble",
		"ubuntu-22.04": "",
		"debian-jammy": "",
		"bookworm":     "",
		"debian-12":    "",
		"jammy-extra":  "",
		"":             "",
	} {
		if got := UbuntuCodename(q); got != want {
			t.Errorf("UbuntuCodename(%q) = %q, want %q", q, got, want)
		}
	}
}
