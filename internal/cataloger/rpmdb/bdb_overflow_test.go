package rpmdb

import (
	"encoding/binary"
	"strings"
	"testing"
)

// P4 of the 2026-11-20 audit: the overflow walk's own two bounds, over a file
// of two overflow pages.
func TestBDB_OverflowRefusesACycleAndAPageFullerThanAPage(t *testing.T) {
	const size = 512
	build := func(next uint32, used uint16) *bdbFile {
		f := &bdbFile{data: make([]byte, 3*size), order: binary.LittleEndian, pageSize: size, pages: 3, lastPgno: 2}
		for pg, n := range map[int]uint32{1: 2, 2: next} {
			p := f.data[pg*size:]
			p[bdbHashMetaAtOff] = bdbOverflow
			f.order.PutUint32(p[16:20], n)
			f.order.PutUint16(p[22:24], used)
		}
		return f
	}
	if got, err := build(0, 100).overflow(1, 150); err != nil || len(got) != 150 {
		t.Fatalf("a sound chain: %d bytes, %v", len(got), err)
	}
	if _, err := build(1, 100).overflow(1, 1000); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("a cycle: %v", err)
	}
	full := uint16(size - bdbPageHeaderLen)
	if _, err := build(0, full).overflow(1, 2*uint32(full)); err != nil {
		t.Errorf("two full pages: %v", err)
	}
	// The slice would run on into the next page, and past the file on the last.
	if _, err := build(0, full+1).overflow(1, 600); err == nil || !strings.Contains(err.Error(), "more than a page") {
		t.Errorf("a page claiming more than it holds: %v", err)
	}
}
