package rpmdb

import (
	"errors"
	"strings"
	"testing"
)

// QA 2026-11-20. A damaged hash page took every record it held with it and
// the read reported a shorter list with no error.
func TestReadBDB_ADamagedHashPageIsRefused(t *testing.T) {
	for name, edit := range map[string]func(f *bdbFile, p []byte){
		"a type byte":  func(_ *bdbFile, p []byte) { p[bdbHashMetaAtOff] = 0 },
		"an odd count": func(f *bdbFile, p []byte) { f.order.PutUint16(p[20:22], f.order.Uint16(p[20:22])-1) },
		"a lower count": func(f *bdbFile, p []byte) {
			f.order.PutUint16(p[20:22], f.order.Uint16(p[20:22])-2)
		},
	} {
		for _, file := range []string{bdbFixture, bdbFixtureBE} {
			b := append([]byte(nil), read(t, file)...)
			f, err := openBDB(b)
			if err != nil {
				t.Fatal(err)
			}
			for pgno := uint32(1); pgno <= f.lastPgno; pgno++ {
				p, err := f.page(pgno)
				if err != nil {
					t.Fatal(err)
				}
				if p[bdbHashMetaAtOff] == bdbHash {
					edit(f, p)
				}
			}
			res, err := ReadBDB(b, "Red Hat:8", bdbPath)
			if !errors.Is(err, ErrBDB) || !(strings.Contains(err.Error(), "a hash page is damaged") || strings.Contains(err.Error(), "an unpaired key")) {
				t.Errorf("%s, %s: %d packages, err %v; want the damaged page refused", name, file, len(res.Packages), err)
			}
		}
	}
}
