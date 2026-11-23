package cataloger_test

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/cataloger/apkdb"
	"github.com/kun9497/assay/internal/cataloger/dpkgdb"
	"github.com/kun9497/assay/internal/cataloger/pacmandb"
)

// QA 2026-11-20. Dependency fields are one line each and real packages exceed
// bufio.Scanner's default 64 KiB, which failed the whole image.
func TestPackageDatabases_ReadALineOverTheScannerDefault(t *testing.T) {
	nl := string(rune(0x0a))
	long := strings.Repeat("libdep0 ", 100<<10/8)

	deb, err := dpkgdb.Parse(strings.NewReader(strings.Join([]string{
		"Package: big", "Status: install ok installed", "Version: 1.0-1", "Architecture: amd64", "Depends: " + long, "",
		"Package: next", "Status: install ok installed", "Version: 2.0-1", "Architecture: amd64", "", ""}, nl)), "Debian:12")
	if err != nil || len(deb) != 2 {
		t.Errorf("dpkg: %d packages, err %v; want both", len(deb), err)
	}
	apkText := strings.Join([]string{"P:big", "V:1.0-r0", "A:x86_64", "D:" + long, "F:usr/bin", "R:big", "",
		"P:next", "V:2.0-r0", "A:x86_64", "", ""}, nl)
	apk, err := apkdb.Parse(strings.NewReader(apkText), "Alpine:v3.20")
	if err != nil || len(apk) != 2 {
		t.Errorf("apk: %d packages, err %v; want both", len(apk), err)
	}
	files, err := apkdb.ParseFiles(strings.NewReader(apkText))
	if err != nil || files["usr/bin/big"] == "" {
		t.Errorf("apk files: %v, err %v; want usr/bin/big owned", files, err)
	}
	pac, err := pacmandb.ParseDesc(strings.NewReader(strings.Join([]string{
		"%NAME%", "big", "", "%VERSION%", "1.0-1", "", "%DEPENDS%", long, ""}, nl)), "Arch:rolling", "desc")
	if err != nil || len(pac) != 1 {
		t.Errorf("pacman: %d packages, err %v; want one", len(pac), err)
	}
}
