package main

import (
	"io"
	"os"
)

// wantColor is D107's whole policy for whether a scan's table output may
// carry ANSI severity colors: the destination has to be a real, colorable
// terminal AND no NO_COLOR opt-out has to be set. Both are required —
// either one being false is enough to keep colors off, on the CAUTION in
// D107's own brief: raw escape bytes in a piped log or a console that
// cannot interpret them are worse than no color at all.
//
// Split into two named booleans — isTerminal (canColor's own answer) and
// noColorEnv (the raw NO_COLOR value, unparsed) — rather than one function
// that reads os.Stdout and os.Getenv("NO_COLOR") itself, because the two
// halves fail for entirely different reasons and need entirely different
// tests: "would the terminal take colors" needs a real character device,
// which no test in this repository has (CI redirects stdout, same as `|
// less` would); "does policy allow them" is a pure function of one
// environment string and needs no I/O at all. Keeping them separate is what
// lets policyAllowsColor's own test drive NO_COLOR="0" through this exact
// function without faking a TTY — the D107 brief's own instruction.
func wantColor(isTerminal bool, noColorEnv string) bool {
	return isTerminal && policyAllowsColor(noColorEnv)
}

// policyAllowsColor reports whether the https://no-color.org convention
// permits color output: PRESENCE of a non-empty NO_COLOR disables it,
// regardless of what it says. "0" is not special-cased to mean "false,
// colors stay on" — that would be envFlag's boolean parsing (used for the
// KISA_ENABLE/NVD_ENABLE family above), and NO_COLOR is not that kind of
// flag. no-color.org's own wording is "when present, and not an empty
// string", which this matches exactly: NO_COLOR=0 disables color under
// that convention, the same as NO_COLOR=anything else.
func policyAllowsColor(noColorEnv string) bool {
	return noColorEnv == ""
}

// stdoutIsTerminal reports whether w is a real, colorable character device:
// concretely an *os.File (never true for a bytes.Buffer or any other
// io.Writer a test hands Run, which is exactly the point — a test double
// can never accidentally read as colorable), whose Stat() reports
// ModeCharDevice, and — on Windows only — whose console mode could actually
// be switched into interpreting ANSI SGR codes (enableVirtualTerminal,
// windows-tagged; the non-Windows counterpart is an unconditional true,
// since every terminal emulator this build targets outside Windows already
// interprets SGR codes without an opt-in syscall).
//
// A type assertion, not os.Stdout read directly: main() is the only caller
// that ever passes the real os.Stdout in (via run's own stdout parameter),
// so this stays exercisable against a redirected file or, in every test,
// simply fails the assertion and returns false — no TTY needed to prove the
// default is off.
func stdoutIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return enableVirtualTerminal(f)
}

// stdoutIsTerminalFunc is the seam run()'s "scan" case actually calls,
// rather than stdoutIsTerminal directly — the same swappable-package-variable
// idiom newNVDAnnotator and newKNVDEnricher already use elsewhere in this
// package, for the identical reason: no test in this repository has a real
// character device to hand run() (CI redirects stdout, same as any `| less`
// would), so proving NO_COLOR overrides a positive terminal answer needs a
// way to STUB that answer. Production never reassigns this; only
// TestRun_NoColorOverridesAPositiveTerminalCheck does.
var stdoutIsTerminalFunc = stdoutIsTerminal
