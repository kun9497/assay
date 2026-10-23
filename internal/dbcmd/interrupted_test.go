package dbcmd

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
)

// interruptedTransfer must recognise a connection reset however the
// platform spells it. On Windows a reset is WSAECONNRESET (errno 10054),
// which is not syscall.ECONNRESET, so a check on that constant alone never
// fires there (D140 review). Any failure of a network READ is the link,
// not the artifact.
func TestInterruptedTransfer(t *testing.T) {
	readErr := func(e error) error {
		return fmt.Errorf("write database: %w", &net.OpError{Op: "read", Net: "tcp", Err: e})
	}
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"unexpected EOF", fmt.Errorf("write database: %w", io.ErrUnexpectedEOF), true},
		{"reset, unix spelling", readErr(syscall.ECONNRESET), true},
		{"reset, windows spelling", readErr(syscall.Errno(10054)), true},
		{"any other read failure", readErr(errors.New("forcibly closed")), true},
		{"not gzip", errors.New("decompress database: gzip: invalid header"), false},
		{"no database layer", errors.New("no layer of type x: this is not an assay database artifact"), false},
	} {
		if got := interruptedTransfer(c.err); got != c.want {
			t.Errorf("%s: interruptedTransfer = %v, want %v", c.name, got, c.want)
		}
	}
}
