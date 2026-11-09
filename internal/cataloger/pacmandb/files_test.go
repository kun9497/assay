package pacmandb

import (
	"strings"
	"testing"
)

func TestParseFiles(t *testing.T) {
	got, err := ParseFiles(strings.NewReader("%FILES%\nusr/\nusr/bin/\nusr/bin/captree\nusr/share/licenses/captree/LICENSE\n\n%BACKUP%\netc/captree.conf\tdeadbeef\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"usr/bin/captree", "usr/share/licenses/captree/LICENSE"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v, want %v", got, want)
	}
}
