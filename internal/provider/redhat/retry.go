package redhat

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// deltaAttempts is how many times one document fetch is tried before the build
// fails (D58).
//
// Three, not more. The delta fetches up to 20,000 documents one at a time, and
// a feed that has genuinely gone away must fail the build quickly rather than
// turn into a very slow death: at three attempts with the backoff below, a
// total outage costs each document about a second and a half before it gives
// up, which is a loud failure rather than a hang.
const deltaAttempts = 3

// deltaBackoff is the pause before attempt n (1-indexed), so 0.5s then 1s.
//
// Short on purpose. This exists for a connection closed mid-handshake, not for
// a service under sustained load — an assay build is one client, and waiting
// minutes to be polite to a feed that is already answering everyone else is
// waiting for nothing.
func deltaBackoff(attempt int) time.Duration {
	return time.Duration(1<<uint(attempt-1)) * 500 * time.Millisecond
}

// retryable reports whether an error is worth another attempt.
//
// The classification is the whole of this file, and both directions are
// mistakes with a cost. Retrying a PERMANENT error turns "the feed changed
// shape" into a slow build that fails anyway, and hides which document was the
// problem behind three identical failures. Not retrying a TRANSIENT one is what
// this exists to fix: a single closed connection killed a 42-minute build on
// 2026-08-13, on document 2,448 of a delta pass.
//
// Retried:
//   - transport failures. A closed connection, a reset, a DNS blip, a timeout.
//     These arrive from http.Client.Do rather than as a status code, and the
//     observed one was a bare `EOF` — the server hung up before answering.
//   - 5xx and 429. The server said it could not answer THIS time.
//   - a truncated body. json.Decode returning an unexpected EOF means the
//     response was cut off mid-document, which is a transport failure wearing a
//     parse error's clothes.
//
// Not retried:
//   - 404, which the caller already reads as a withdrawal (D49) and never
//     reaches here.
//   - any other 4xx. The request is wrong and will be wrong again.
//   - a parse error that is not truncation. A document that is not JSON will
//     not become JSON, and retrying it would delay a real signal that the feed
//     changed shape.
//   - context cancellation, which is the caller deciding to stop. Retrying
//     through it would ignore the one instruction that outranks this.
func retryable(err error, status int) bool {
	if status != 0 {
		return status == http.StatusTooManyRequests || status >= 500
	}
	if err == nil {
		return false
	}
	// Checked FIRST. A cancelled context surfaces as a transport error, and
	// treating it as transient would retry against a deadline that has already
	// passed — three times, per document, for the rest of the pass.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	// url.Error wrapping a bare EOF is what the observed failure looked like,
	// and errors.Is above catches it. Anything else that reached here is not
	// recognisably transient, and guessing would retry parse errors.
	return false
}

// sleepOrDone waits for d, or returns the context's error if it ends first.
// Returning early on cancellation is what keeps a cancelled pass from spending
// deltaAttempts backoffs per remaining document before noticing.
func sleepOrDone(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
