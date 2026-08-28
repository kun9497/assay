//go:build !windows

package main

import "os"

// enableVirtualTerminal is the no-op counterpart to color_windows.go's own
// version: every terminal emulator this build targets outside Windows
// already interprets ANSI SGR codes without an explicit opt-in syscall, so
// there is no mode to flip. It exists only so stdoutIsTerminal can call one
// name on every platform rather than branching on GOOS itself.
func enableVirtualTerminal(f *os.File) bool {
	return true
}
