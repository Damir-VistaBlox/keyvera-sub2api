-- Recreate ops_alert_silences: fixes 037_ops_alert_silences.sql, whose embedded
-- "-- +goose Down" section ran in the same transaction as its "-- +goose Up"
-- section (this project's migration runner executes each file as-is and does
-- not parse goose Up/Down markers -- see migrations/README.md). The net effect
-- of 037 was CREATE TABLE immediately followed by DROP TABLE, so the table has
-- never actually existed in any environment that ran 037, even though
-- internal/repository/ops_repo_alerts.go (CreateAlertSilence, IsAlertSilenced)
-- has always assumed it does. See GitHub issue #7.
--
-- Forward-only, matches 037's original intended schema exactly.

CREATE TABLE IF NOT EXISTS ops_alert_silences (
    id BIGSERIAL PRIMARY KEY,

    rule_id BIGINT NOT NULL,
    platform VARCHAR(64) NOT NULL,
    group_id BIGINT,
    region VARCHAR(64),

    until TIMESTAMPTZ NOT NULL,
    reason TEXT,

    created_by BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ops_alert_silences_lookup
    ON ops_alert_silences (rule_id, platform, group_id, region, until);
