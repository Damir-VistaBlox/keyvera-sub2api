package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// UpdateUpstreamBillingProbeSnapshot stores a probe result only while the
// network identity used by that probe is still current.
func (r *accountRepository) UpdateUpstreamBillingProbeSnapshot(
	ctx context.Context,
	account *service.Account,
	snapshot *service.UpstreamBillingProbeSnapshot,
	rateMultiplier *float64,
) error {
	if account == nil || snapshot == nil {
		return service.ErrAccountNilInput
	}
	if snapshot.Status != service.UpstreamBillingProbeStatusOK {
		rateMultiplier = nil
	}
	if dbent.TxFromContext(ctx) == nil {
		tx, err := r.client.Tx(ctx)
		if errors.Is(err, dbent.ErrTxStarted) {
			return r.updateUpstreamBillingProbeSnapshotInTx(ctx, account, snapshot, rateMultiplier)
		}
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()

		if err := r.updateUpstreamBillingProbeSnapshotInTx(dbent.NewTxContext(ctx, tx), account, snapshot, rateMultiplier); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		// The durable outbox event is committed with the snapshot. This direct
		// cache write only reduces visibility latency on the current instance.
		r.syncSchedulerAccountSnapshot(ctx, account.ID)
		return nil
	}
	return r.updateUpstreamBillingProbeSnapshotInTx(ctx, account, snapshot, rateMultiplier)
}

func (r *accountRepository) updateUpstreamBillingProbeSnapshotInTx(
	ctx context.Context,
	account *service.Account,
	snapshot *service.UpstreamBillingProbeSnapshot,
	rateMultiplier *float64,
) error {
	payload, err := json.Marshal(map[string]any{service.UpstreamBillingProbeExtraKey: snapshot})
	if err != nil {
		return err
	}
	credentials, err := json.Marshal(account.Credentials)
	if err != nil {
		return err
	}
	var expectedSnapshot any
	if account.Extra != nil {
		expectedSnapshot = account.Extra[service.UpstreamBillingProbeExtraKey]
	}
	expectedSnapshotJSON, err := json.Marshal(expectedSnapshot)
	if err != nil {
		return err
	}
	var expectedEnabled any
	if account.Extra != nil {
		expectedEnabled = account.Extra[service.UpstreamBillingProbeEnabledExtraKey]
	}
	expectedEnabledJSON, err := json.Marshal(expectedEnabled)
	if err != nil {
		return err
	}
	var expectedRateSyncEnabled any
	if account.Extra != nil {
		expectedRateSyncEnabled = account.Extra[service.UpstreamBillingRateSyncEnabledExtraKey]
	}
	expectedRateSyncEnabledJSON, err := json.Marshal(expectedRateSyncEnabled)
	if err != nil {
		return err
	}
	client := clientFromContext(ctx, r.client)
	proxyMatches, err := lockAndMatchProbeProxyIdentity(ctx, client, account)
	if err != nil {
		return err
	}
	if !proxyMatches {
		return service.ErrUpstreamBillingProbeIdentityChanged
	}
	var proxyID any
	if account.ProxyID != nil {
		proxyID = *account.ProxyID
	}
	result, err := client.ExecContext(ctx, `
		UPDATE accounts
		SET
			extra = COALESCE(extra, '{}'::jsonb) || $1::jsonb,
			rate_multiplier = CASE
				WHEN $10::numeric IS NOT NULL
					AND extra @> '{"upstream_billing_probe_enabled": true}'::jsonb
					AND extra @> '{"upstream_billing_rate_sync_enabled": true}'::jsonb
				THEN $10::numeric
				ELSE rate_multiplier
			END,
			updated_at = NOW()
		WHERE id = $2
			AND platform = $3
			AND type = $4
			AND credentials = $5::jsonb
			AND proxy_id IS NOT DISTINCT FROM $6
			AND COALESCE(extra -> 'upstream_billing_probe', 'null'::jsonb) = $7::jsonb
			AND COALESCE(extra -> 'upstream_billing_probe_enabled', 'null'::jsonb) = $8::jsonb
			AND COALESCE(extra -> 'upstream_billing_rate_sync_enabled', 'null'::jsonb) = $9::jsonb
			AND deleted_at IS NULL
	`, string(payload), account.ID, account.Platform, account.Type, string(credentials), proxyID, string(expectedSnapshotJSON), string(expectedEnabledJSON), string(expectedRateSyncEnabledJSON), rateMultiplier)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return service.ErrUpstreamBillingProbeIdentityChanged
	}
	return enqueueSchedulerOutbox(ctx, client, service.SchedulerOutboxEventAccountChanged, &account.ID, nil, nil)
}

func lockAndMatchProbeProxyIdentity(ctx context.Context, client *dbent.Client, account *service.Account) (bool, error) {
	if account.ProxyID == nil {
		return true, nil
	}
	rows, err := client.QueryContext(ctx, `
		SELECT protocol, host, port, COALESCE(username, ''), COALESCE(password, ''), status
		FROM proxies
		WHERE id = $1 AND deleted_at IS NULL
		FOR SHARE
	`, *account.ProxyID)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return false, err
		}
		return account.Proxy == nil, nil
	}
	if account.Proxy == nil || account.Proxy.ID != *account.ProxyID {
		return false, nil
	}
	var current proxyProbeIdentity
	if err := rows.Scan(&current.protocol, &current.host, &current.port, &current.username, &current.password, &current.status); err != nil {
		return false, err
	}
	return current == proxyProbeIdentityFromService(account.Proxy), rows.Err()
}

func upstreamBillingProbeExplicitlyDisabled(extra map[string]any) bool {
	enabled, ok := extra[service.UpstreamBillingProbeEnabledExtraKey].(bool)
	return ok && !enabled
}

func upstreamBillingProbeSnapshotClearRequested(extra map[string]any) bool {
	value, ok := extra[service.UpstreamBillingProbeExtraKey]
	return ok && value == nil
}

func ollamaCloudUsageSnapshotClearRequested(extra map[string]any) bool {
	value, ok := extra[service.OllamaCloudUsageSnapshotExtraKey]
	return ok && value == nil
}

// ListDueUpstreamBillingProbeAccounts bounds result hydration and network work
// to limit. PostgreSQL must still filter and order all enabled candidates;
// MATERIALIZED avoids repeating the defensive timestamp parse expression.
// Go writes next_probe_at via RFC3339Nano (up to 9 fractional digits) while
// jsonpath datetime() parses at most microseconds, so fractions beyond 6
// digits are trimmed first — mirroring ListDueOllamaCloudUsageAccounts.
// Without this, every nanosecond timestamp is treated as malformed and the
// fail-open ordering pins the cycle to the lowest account IDs, starving the
// rest of the pool.
func (r *accountRepository) ListDueUpstreamBillingProbeAccounts(ctx context.Context, now time.Time, limit int) ([]service.Account, error) {
	if limit <= 0 {
		return []service.Account{}, nil
	}
	if r.sql == nil {
		return nil, errors.New("account repository SQL executor not configured")
	}

	rows, err := r.sql.QueryContext(ctx, `
		WITH candidates AS (
			SELECT
				id,
				extra #>> '{upstream_billing_probe,status}' AS probe_status,
				extra #>> '{upstream_billing_probe,next_probe_at}' AS next_probe_at
			FROM accounts
			WHERE deleted_at IS NULL
				AND status = 'active'
				AND type = 'apikey'
				AND extra @> '{"upstream_billing_probe_enabled": true}'::jsonb
		), parsed AS MATERIALIZED (
			SELECT
				id,
				probe_status,
				next_probe_at,
				next_probe_at ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$' AS rfc3339_shape,
				jsonb_path_query_first_tz(
					jsonb_build_object(
						'value',
						replace(regexp_replace(regexp_replace(
							next_probe_at,
							'(\.[0-9]{6})[0-9]+(Z|[+-][0-9]{2}:[0-9]{2})$',
							'\1\2'
						), 'Z$', '+00:00'), 'T', ' ')
					),
					'$.value.datetime()',
					'{}'::jsonb,
					true
				) #>> '{}' AS parsed_next_probe_at
			FROM candidates
		), normalized AS (
			SELECT
				id,
				probe_status,
				next_probe_at,
				parsed_next_probe_at,
				rfc3339_shape AND parsed_next_probe_at IS NOT NULL AS valid_next_probe_at
			FROM parsed
		)
		SELECT id
		FROM normalized
		WHERE probe_status NOT IN ('ok', 'unsupported', 'failed')
			OR probe_status IS NULL
			OR next_probe_at IS NULL
			OR NOT valid_next_probe_at
			OR CASE WHEN valid_next_probe_at THEN parsed_next_probe_at::timestamptz <= $1 ELSE FALSE END
		ORDER BY
			CASE
				WHEN probe_status NOT IN ('ok', 'unsupported', 'failed')
					OR probe_status IS NULL
					OR next_probe_at IS NULL
					OR NOT valid_next_probe_at
				THEN 0
				ELSE 1
			END ASC,
			CASE WHEN valid_next_probe_at THEN parsed_next_probe_at::timestamptz END ASC NULLS FIRST,
			id ASC
		LIMIT $2
	`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	ids := make([]int64, 0, limit)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return []service.Account{}, nil
	}

	accounts, err := r.GetByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]service.Account, 0, len(accounts))
	for _, account := range accounts {
		if account != nil {
			out = append(out, *account)
		}
	}
	return out, nil
}
