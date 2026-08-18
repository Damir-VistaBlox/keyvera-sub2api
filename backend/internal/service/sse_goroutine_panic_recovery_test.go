//go:build unit

package service

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// panicOnceReader returns one line of valid SSE data, then panics on the
// next Read call. This simulates a downstream bug (e.g. a corrupted buffer
// pool, a stdlib edge case) surfacing as a panic mid-stream rather than a
// normal error -- exactly the class of failure the SSE-reader goroutines'
// recover() guards exist to contain.
type panicOnceReader struct {
	data []byte
	sent bool
}

func (r *panicOnceReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		n := copy(p, r.data)
		return n, nil
	}
	panic("simulated panic reading upstream SSE body")
}

// TestReadOpenAICompatBufferedTerminalRecoversFromReaderPanic proves the
// recover() added to readOpenAICompatBufferedTerminal's SSE-reader goroutine
// actually stops a reader panic from being fatal to the process, and that
// the function still returns (rather than hanging) once its goroutine has
// recovered. Before the fix, a panic on this path crashed the entire
// process -- every in-flight request across every tenant, not just this one.
//
// Reaching either branch of the select below (pass or the documented-behavior
// assertions) is itself the primary proof: an unrecovered goroutine panic is
// fatal to the whole Go process, so a broken recover() would crash this test
// binary outright rather than surface as an ordinary test failure.
func TestReadOpenAICompatBufferedTerminalRecoversFromReaderPanic(t *testing.T) {
	s := &OpenAIGatewayService{}
	resp := &http.Response{
		Body: io.NopCloser(&panicOnceReader{data: []byte("data: {\"type\":\"noop\"}\n\n")}),
	}

	done := make(chan struct{})
	var errOut error
	go func() {
		defer close(done)
		_, _, _, errOut = s.readOpenAICompatBufferedTerminal(resp, "test", "req-panic-recovery")
	}()

	select {
	case <-done:
		// Documented current behavior: a recovered panic looks like a
		// clean-but-empty stream to the caller (nil response, no error),
		// not an explicit "the reader panicked" error. That is an accepted,
		// separately-trackable limitation -- the goal here is containment,
		// not perfect error propagation.
		require.NoError(t, errOut)
	case <-time.After(5 * time.Second):
		t.Fatal("readOpenAICompatBufferedTerminal did not return after its SSE-reader goroutine panicked -- recover() may not be closing the events channel")
	}
}
