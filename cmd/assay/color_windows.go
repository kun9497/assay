//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVirtualTerminal turns on ENABLE_VIRTUAL_TERMINAL_PROCESSING on f's
// console mode — the bit that makes cmd.exe and older PowerShell hosts
// interpret ANSI SGR codes instead of printing them as literal garble.
// Windows Terminal already has this on by default, but a console opened
// directly does not, and D107's own CAUTION is explicit: colors must never
// reach a console that cannot render them, so this is checked and enabled
// before wantColor is ever allowed to say yes on this platform.
//
// golang.org/x/sys is promoted to a direct dependency in go.mod for this
// call (D107) — it was already an INDIRECT one, pulled in transitively
// through go-containerregistry, so this is the same zero-cost promotion
// yaml.v3 (D102) and klauspost/compress made: a line moved in go.mod, no
// new code linked that was not already being built.
//
// Any failure here — an unrecognized handle, a console predating this mode
// bit, running under a pipe GetConsoleMode rejects — leaves colors OFF
// (stdoutIsTerminal's own caller returns false) rather than risking raw
// escape bytes printed as literal text.
func enableVirtualTerminal(f *os.File) bool {
	handle := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true // already on - Windows Terminal's own default
	}
	if err := windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return false
	}
	return true
}
