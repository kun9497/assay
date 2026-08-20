package fedora

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// pageAttempts is how many times one page fetch is tried before the release
// (and so the build) fails. Three, the same figure D58 chose for redhat's
// document fetch and for the identical reason: Bodhi pages one at a time,
// so a release that has genuinely gone away must fail loudly rather than
// retry forever against a feed that is not coming back.
const pageAttempts = 3

// pageBackoff is the pause before attempt n (1-indexed), so 0.5s then 1s --
// the exact schedule redhat.deltaBackoff uses, reused rather than
// reinvented: short on purpose, because this exists for "the bot-front
// answered 429/5xx a moment ago", not for a service under sustained load.
func pageBackoff(attempt int) time.Duration {
	return time.Duration(1<<uint(attempt-1)) * 500 * time.Millisecond
}

// retryable reports whether an error is worth another attempt.
//
// Narrower than redhat.retryable on purpose -- "honest retry ONLY on
// 429/5xx" was the design brief for this slice, not the fuller transient-
// transport-error set D58 built for a 42-minute, 20,000-document Red Hat
// delta pass. Bodhi is a much smaller, much slower (bot-fronted) feed, and a
// retry policy that also chased connection resets and truncated bodies here
// would risk quietly retrying past an Anubis challenge response rather than
// surfacing it. What is kept from redhat.retryable is the CLASSIFICATION
// ORDER: cancellation is checked before anything else, including the
// status, because retrying through the caller's own "stop" would ignore the
// one instruction that outranks this.
//
// Retried: 429 (Bodhi/Anubis said slow down) and 5xx (the server could not
// answer this time).
//
// Not retried: any other 4xx (the request is wrong and will be wrong
// again), a network-level failure with no status at all (status 0), a
// decode error, and context cancellation/deadline.
func retryable(err error, status int) bool {
	if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return false
	}
	return status == http.StatusTooManyRequests || status >= 500
}

// sleepOrDone waits for d, or returns the context's error if it ends first
// -- redhat.sleepOrDone's own doc comment explains why this matters:
// without it a cancelled pass spends pageAttempts backoffs per remaining
// page before noticing.
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
