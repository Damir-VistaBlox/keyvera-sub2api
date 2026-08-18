//go:build unit

package service

import (
	"testing"

	"github.com/gin-gonic/gin"
)

// TestMain sets gin's mode once, before any test runs. Individual tests used
// to each call gin.SetMode(gin.TestMode) themselves (771 call sites across
// 99 files) -- harmless when tests run sequentially, but gin.SetMode mutates
// an unsynchronized package-level global by design (gin expects it to be set
// once at program startup, not from concurrent callers), so with this
// package's widespread use of t.Parallel() those calls raced with each
// other under `go test -race`. All of them set the same value, so removing
// the redundant per-test calls changes no behavior. See #29.
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	m.Run()
}
