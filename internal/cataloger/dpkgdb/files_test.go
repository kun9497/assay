package dpkgdb

import (
	"strings"
	"testing"
)

func TestParseFileList(t *testing.T) {
	got, err := ParseFileList(strings.NewReader("/.\n/usr\n/usr/lib/node_modules/npm/package.json\n\n/usr/share/doc/npm/changelog.gz  \n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr", "/usr/lib/node_modules/npm/package.json", "/usr/share/doc/npm/changelog.gz"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestListOwner(t *testing.T) {
	for _, tc := range []struct{ base, name, arch string }{
		{"npm.list", "npm", ""},
		{"libc6:amd64.list", "libc6", "amd64"},
		{"libc6:amd64.md5sums", "", ""},
		{"files", "", ""},
	} {
		if n, a := ListOwner(tc.base); n != tc.name || a != tc.arch {
			t.Errorf("ListOwner(%q) = %q, %q; want %q, %q", tc.base, n, a, tc.name, tc.arch)
		}
	}
}
