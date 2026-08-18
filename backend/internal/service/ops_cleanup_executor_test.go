//go:build unit

package service

import (
	"context"
	"testing"
	"time"
)

func TestOpsCleanupRunOneAcceptsAllConfiguredTargets(t *testing.T) {
	// Mirrors runCleanupOnce's targets slice in ops_cleanup_service.go exactly.
	pairs := []struct{ table, timeCol string }{
		{"ops_error_logs", "created_at"},
		{"ops_ingress_reject_aggregates", "bucket_start"},
		{"ops_alert_events", "created_at"},
		{"ops_system_logs", "created_at"},
		{"ops_system_log_cleanup_audits", "created_at"},
		{"ops_system_metrics", "created_at"},
		{"ops_metrics_hourly", "bucket_start"},
		{"ops_metrics_daily", "bucket_date"},
	}
	for _, p := range pairs {
		t.Run(p.table, func(t *testing.T) {
			for _, truncate := range []bool{false, true} {
				// db=nil short-circuits deleteOldRowsByID/truncateOpsTable to (0, nil)
				// after validation passes, isolating the allowlist check itself.
				n, err := opsCleanupRunOne(context.Background(), nil, truncate, time.Now(), p.table, p.timeCol, false, 0)
				if err != nil {
					t.Fatalf("table=%q timeCol=%q truncate=%v: %v", p.table, p.timeCol, truncate, err)
				}
				if n != 0 {
					t.Fatalf("expected 0 rows with nil db, got %d", n)
				}
			}
		})
	}
}

func TestOpsCleanupRunOneRejectsUnallowlistedIdentifiers(t *testing.T) {
	_, err := opsCleanupRunOne(context.Background(), nil, false, time.Now(), "users; DROP TABLE users;--", "created_at", false, 0)
	if err == nil {
		t.Fatal("expected an error for a non-allowlisted table name")
	}
	_, err = opsCleanupRunOne(context.Background(), nil, false, time.Now(), "ops_error_logs", "id = 1; --", false, 0)
	if err == nil {
		t.Fatal("expected an error for a non-allowlisted time column")
	}
}
