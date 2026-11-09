package apkdb

import (
	"strings"
	"testing"
)

func TestParseFiles(t *testing.T) {
	db := "C:Q1abc=\nP:busybox-binsh\nV:1.36.1-r15\nA:x86_64\nF:bin\nR:sh\nF:usr/bin\nR:tool\nR:env\n\n" +
		"P:gosu\nV:1.17-r2\nF:usr/bin\nR:gosu\nZ:Q1xyz=\n\n" +
		// A record with files but no name owns nothing; an R: before any F:
		// is malformed and skipped.
		"V:9\nF:etc\nR:orphan\n\nP:early\nR:nodir\nF:var\nR:ok\nP:next\nR:inherited\nF:srv\nR:own\n"
	got, err := ParseFiles(strings.NewReader(db))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"bin/sh": "busybox-binsh", "usr/bin/tool": "busybox-binsh", "usr/bin/env": "busybox-binsh", "usr/bin/gosu": "gosu", "var/ok": "early", "srv/own": "next"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for p, n := range want {
		if got[p] != n {
			t.Errorf("%s owned by %q, want %q", p, got[p], n)
		}
	}
}
