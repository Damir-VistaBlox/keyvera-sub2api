package service

import (
	"bufio"
	"runtime/debug"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

// startSSEReader spawns a goroutine that scans scanner line-by-line,
// converting each line to an event via newLineEvent and forwarding it on the
// returned channel, until EOF, a scan error (converted via newErrEvent), or
// done is closed. The channel is always closed when the goroutine returns,
// covering the normal exit, the done-closed exit, and the panic-recovered
// exit alike, so a consumer ranging over it always terminates.
//
// scanBuf is optional: pass a non-nil pooled buffer to have it returned via
// putSSEScannerBuf64K when the goroutine exits (for scanners built from the
// pool), or nil for scanners that don't use one.
//
// onLine, if non-nil, runs synchronously for each scanned line before the
// event is sent -- e.g. to update a liveness timestamp read by an interval
// timer elsewhere. It must not block or send on the returned channel itself.
//
// If the scan loop panics (the reason this helper exists: a bug in a
// buffer-pool or scanner edge case surfacing as a panic must not be fatal to
// the whole process), the panic is recovered and logged via
// logger.LegacyPrintf(logComponent, ...); the caller sees a closed channel
// with no final event, the same as an ordinary clean end of stream.
func startSSEReader[T any](
	scanner *bufio.Scanner,
	scanBuf *sseScannerBuf64K,
	done <-chan struct{},
	onLine func(line string),
	newLineEvent func(line string) T,
	newErrEvent func(err error) T,
	logComponent, logSite string,
) <-chan T {
	events := make(chan T, 16)
	sendEvent := func(ev T) bool {
		select {
		case events <- ev:
			return true
		case <-done:
			return false
		}
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.LegacyPrintf(logComponent, "ALERT: panic in %s SSE reader goroutine: %v\n%s", logSite, r, debug.Stack())
			}
		}()
		if scanBuf != nil {
			defer putSSEScannerBuf64K(scanBuf)
		}
		defer close(events)
		for scanner.Scan() {
			line := scanner.Text()
			if onLine != nil {
				onLine(line)
			}
			if !sendEvent(newLineEvent(line)) {
				return
			}
		}
		if err := scanner.Err(); err != nil {
			_ = sendEvent(newErrEvent(err))
		}
	}()
	return events
}
