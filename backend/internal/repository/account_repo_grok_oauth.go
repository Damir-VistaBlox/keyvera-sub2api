package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *accountRepository) credentialsMatchSQLForStorage(column, jsonArg, digestArg string) string {
	if r != nil && r.encryptor != nil {
		return accountCredentialsMatchSQL(column, jsonArg, digestArg)
	}
	return column + " = " + jsonArg + "::jsonb"
}

func (r *accountRepository) credentialsJSONForStorage(credentials map[string]any) (string, string, error) {
	if r != nil && r.encryptor != nil {
		return r.credentialsStorageJSONAndDigest(credentials)
	}
	payload, err := json.Marshal(normalizeJSONMap(credentials))
	if err != nil {
		return "", "", err
	}
	return string(payload), "", nil
}

func (r *accountRepository) appendDigestArg(args []any, digest string) []any {
	if r != nil && r.encryptor != nil {
		return append(args, digest)
	}
	return args
}

func (r *accountRepository) snapshotDigestArg(snapshot service.GrokCredentialMutationSnapshot) []any {
	if r != nil && r.encryptor != nil {
		return []any{sha256Hex([]byte(snapshot.CredentialsJSON))}
	}
	return nil
}

func (r *accountRepository) SetGrokCredentialErrorIfMatch(
	ctx context.Context,
	id int64,
	snapshot service.GrokCredentialMutationSnapshot,
	errorMsg string,
) (bool, error) {
	credentialsMatchSQL := r.credentialsMatchSQLForStorage("a.credentials", "$7", "$11")
	args := []any{
		service.StatusError,
		errorMsg,
		id,
		service.StatusActive,
		service.PlatformGrok,
		service.AccountTypeOAuth,
		snapshot.CredentialsJSON,
		snapshot.ProxyID,
		string(service.GrokCredentialReasonProxyInvalid),
		service.SchedulerOutboxEventAccountChanged,
	}
	args = append(args, r.snapshotDigestArg(snapshot)...)
	result, err := r.sql.ExecContext(ctx, `
		WITH updated AS (
		UPDATE accounts AS a
		SET status = $1,
			error_message = $2,
			schedulable = false,
			updated_at = NOW()
		WHERE a.id = $3
			AND a.deleted_at IS NULL
			AND a.status = $4
			AND a.platform = $5
			AND a.type = $6
			AND a.schedulable IS TRUE
			AND (a.temp_unschedulable_until IS NULL OR a.temp_unschedulable_until <= NOW())
			AND (a.rate_limit_reset_at IS NULL OR a.rate_limit_reset_at <= NOW())
			AND (a.overload_until IS NULL OR a.overload_until <= NOW())
			AND (a.auto_pause_on_expired IS NOT TRUE OR a.expires_at IS NULL OR a.expires_at > NOW())
				AND `+credentialsMatchSQL+`
			AND a.proxy_id IS NOT DISTINCT FROM $8
			AND ($2 <> $9 OR (
				a.proxy_id IS NOT NULL AND NOT EXISTS (
					SELECT 1 FROM proxies p WHERE p.id = a.proxy_id AND p.deleted_at IS NULL
				)
			))
		RETURNING a.id
		)
		INSERT INTO scheduler_outbox (event_type, account_id, group_id, payload)
		SELECT $10, updated.id, NULL, NULL FROM updated
		`, args...)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return false, err
	}
	r.syncSchedulerAccountSnapshotDetached(ctx, id)
	return true, nil
}

// SetGrokOAuthErrorIfCredentialsUnchanged atomically quarantines a structurally
// invalid Grok OAuth account only if it is still active and its complete JSONB
// credential document matches the state observed by reconciliation. Exact
// JSONB equality includes _token_version when present and prevents a concurrent
// reauthorization from being overwritten by a stale check-then-mutate path.
func (r *accountRepository) SetGrokOAuthErrorIfCredentialsUnchanged(
	ctx context.Context,
	id int64,
	expectedCredentials map[string]any,
	errorMsg string,
) (bool, error) {
	if r == nil || r.sql == nil {
		return false, errors.New("account repository SQL executor is not configured")
	}
	expectedJSON, expectedDigest, err := r.credentialsJSONForStorage(expectedCredentials)
	if err != nil {
		return false, err
	}
	credentialsMatchSQL := r.credentialsMatchSQLForStorage("a.credentials", "$7", "$9")
	refreshTokenAbsentSQL := "NULLIF(BTRIM(a.credentials->>'refresh_token'), '') IS NULL"
	if r.encryptor != nil {
		refreshTokenAbsentSQL = accountCredentialsRefreshTokenAbsentSQL("a.credentials")
	}
	args := []any{
		service.StatusError,
		errorMsg,
		id,
		service.PlatformGrok,
		service.AccountTypeOAuth,
		service.StatusActive,
		expectedJSON,
		service.SchedulerOutboxEventAccountChanged,
	}
	args = r.appendDigestArg(args, expectedDigest)
	result, err := r.sql.ExecContext(ctx, `
		WITH updated AS (
		UPDATE accounts AS a
		SET status = $1,
			error_message = $2,
			schedulable = FALSE,
			updated_at = NOW()
		WHERE a.id = $3
			AND a.deleted_at IS NULL
			AND a.platform = $4
			AND a.type = $5
			AND a.status = $6
				AND `+credentialsMatchSQL+`
				AND `+refreshTokenAbsentSQL+`
		RETURNING a.id
		)
		INSERT INTO scheduler_outbox (event_type, account_id, group_id, payload)
		SELECT $8, updated.id, NULL, NULL FROM updated
	`, args...)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rowsAffected == 0 {
		return false, nil
	}
	r.syncSchedulerAccountSnapshotDetached(ctx, id)
	return true, nil
}

// UpdateGrokOAuthCredentialsIfUnchanged persists provider-issued replacement
// credentials only while the complete Grok OAuth credential document and
// proxy still match the fresh snapshot used by the upstream refresh call. The
// scheduler outbox insert is part of the same PostgreSQL statement, so a
// durable invalidation failure rolls the credential update back as well.
func (r *accountRepository) UpdateGrokOAuthCredentialsIfUnchanged(
	ctx context.Context,
	id int64,
	expectedCredentials map[string]any,
	expectedProxyID *int64,
	credentials map[string]any,
) (bool, error) {
	if r == nil || r.sql == nil {
		return false, errors.New("account repository SQL executor is not configured")
	}
	expectedJSON, expectedDigest, err := r.credentialsJSONForStorage(expectedCredentials)
	if err != nil {
		return false, err
	}
	credentialsJSON, _, err := r.credentialsJSONForStorage(credentials)
	if err != nil {
		return false, err
	}
	credentialsMatchSQL := r.credentialsMatchSQLForStorage("a.credentials", "$5", "$8")
	args := []any{
		credentialsJSON,
		id,
		service.PlatformGrok,
		service.AccountTypeOAuth,
		expectedJSON,
		expectedProxyID,
		service.SchedulerOutboxEventAccountChanged,
	}
	args = r.appendDigestArg(args, expectedDigest)
	result, err := r.sql.ExecContext(ctx, `
		WITH updated AS (
		UPDATE accounts AS a
		SET credentials = $1::jsonb,
			updated_at = NOW()
		WHERE a.id = $2
			AND a.deleted_at IS NULL
			AND a.platform = $3
			AND a.type = $4
			AND `+credentialsMatchSQL+`
			AND a.proxy_id IS NOT DISTINCT FROM $6
		RETURNING a.id
		)
		INSERT INTO scheduler_outbox (event_type, account_id, group_id, payload)
		SELECT $7, updated.id, NULL, NULL FROM updated
	`, args...)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rowsAffected == 0 {
		return false, nil
	}
	r.syncSchedulerAccountSnapshotDetached(ctx, id)
	return true, nil
}

// SetGrokOAuthRefreshErrorIfCredentialsUnchanged is the background-refresh
// counterpart to reconciliation's stricter missing-refresh-token mutation. It
// matches the complete credential document used by the failed upstream attempt
// but deliberately does not require the refresh token to be absent.
func (r *accountRepository) SetGrokOAuthRefreshErrorIfCredentialsUnchanged(
	ctx context.Context,
	id int64,
	expectedCredentials map[string]any,
	expectedProxyID *int64,
	errorMsg string,
) (bool, error) {
	if r == nil || r.sql == nil {
		return false, errors.New("account repository SQL executor is not configured")
	}
	expectedJSON, expectedDigest, err := r.credentialsJSONForStorage(expectedCredentials)
	if err != nil {
		return false, err
	}
	credentialsMatchSQL := r.credentialsMatchSQLForStorage("a.credentials", "$7", "$10")
	args := []any{
		service.StatusError,
		errorMsg,
		id,
		service.PlatformGrok,
		service.AccountTypeOAuth,
		service.StatusActive,
		expectedJSON,
		expectedProxyID,
		service.SchedulerOutboxEventAccountChanged,
	}
	args = r.appendDigestArg(args, expectedDigest)
	result, err := r.sql.ExecContext(ctx, `
		WITH updated AS (
		UPDATE accounts AS a
		SET status = $1,
			error_message = $2,
			schedulable = FALSE,
			updated_at = NOW()
		WHERE a.id = $3
			AND a.deleted_at IS NULL
			AND a.platform = $4
			AND a.type = $5
			AND a.status = $6
				AND `+credentialsMatchSQL+`
			AND a.proxy_id IS NOT DISTINCT FROM $8
		RETURNING a.id
		)
		INSERT INTO scheduler_outbox (event_type, account_id, group_id, payload)
		SELECT $9, updated.id, NULL, NULL FROM updated
	`, args...)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rowsAffected == 0 {
		return false, nil
	}
	r.syncSchedulerAccountSnapshotDetached(ctx, id)
	return true, nil
}

// SetGrokOAuthRefreshTempUnschedulableIfCredentialsUnchanged applies a bounded
// transient refresh quarantine only while the active Grok OAuth credential
// document still matches the exact upstream attempt.
func (r *accountRepository) SetGrokOAuthRefreshTempUnschedulableIfCredentialsUnchanged(
	ctx context.Context,
	id int64,
	expectedCredentials map[string]any,
	expectedProxyID *int64,
	until time.Time,
	reason string,
) (bool, error) {
	if r == nil || r.sql == nil {
		return false, errors.New("account repository SQL executor is not configured")
	}
	expectedJSON, expectedDigest, err := r.credentialsJSONForStorage(expectedCredentials)
	if err != nil {
		return false, err
	}
	credentialsMatchSQL := r.credentialsMatchSQLForStorage("a.credentials", "$7", "$10")
	args := []any{
		until,
		reason,
		id,
		service.PlatformGrok,
		service.AccountTypeOAuth,
		service.StatusActive,
		expectedJSON,
		expectedProxyID,
		service.SchedulerOutboxEventAccountChanged,
	}
	args = r.appendDigestArg(args, expectedDigest)
	result, err := r.sql.ExecContext(ctx, `
		WITH updated AS (
		UPDATE accounts AS a
		SET temp_unschedulable_until = $1,
			temp_unschedulable_reason = $2,
			updated_at = NOW()
		WHERE a.id = $3
			AND a.deleted_at IS NULL
			AND a.platform = $4
			AND a.type = $5
			AND a.status = $6
				AND `+credentialsMatchSQL+`
			AND a.proxy_id IS NOT DISTINCT FROM $8
			AND (a.temp_unschedulable_until IS NULL OR a.temp_unschedulable_until < $1)
		RETURNING a.id
		)
		INSERT INTO scheduler_outbox (event_type, account_id, group_id, payload)
		SELECT $9, updated.id, NULL, NULL FROM updated
	`, args...)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rowsAffected == 0 {
		return false, nil
	}
	r.syncSchedulerAccountSnapshotDetached(ctx, id)
	return true, nil
}

func (r *accountRepository) SetGrokCredentialTempUnschedulableIfMatch(
	ctx context.Context,
	id int64,
	snapshot service.GrokCredentialMutationSnapshot,
	until time.Time,
	reason string,
) (bool, error) {
	credentialsMatchSQL := r.credentialsMatchSQLForStorage("a.credentials", "$7", "$10")
	args := []any{
		until,
		reason,
		id,
		service.StatusActive,
		service.PlatformGrok,
		service.AccountTypeOAuth,
		snapshot.CredentialsJSON,
		snapshot.ProxyID,
		service.SchedulerOutboxEventAccountChanged,
	}
	args = append(args, r.snapshotDigestArg(snapshot)...)
	result, err := r.sql.ExecContext(ctx, `
		WITH updated AS (
		UPDATE accounts AS a
		SET temp_unschedulable_until = CASE
				WHEN a.temp_unschedulable_until IS NULL OR a.temp_unschedulable_until < $1 THEN $1
				ELSE a.temp_unschedulable_until
			END,
			temp_unschedulable_reason = $2,
			updated_at = NOW()
		WHERE a.id = $3
			AND a.deleted_at IS NULL
			AND a.status = $4
			AND a.platform = $5
			AND a.type = $6
			AND a.schedulable IS TRUE
			AND (a.temp_unschedulable_until IS NULL OR a.temp_unschedulable_until <= NOW())
			AND (a.rate_limit_reset_at IS NULL OR a.rate_limit_reset_at <= NOW())
			AND (a.overload_until IS NULL OR a.overload_until <= NOW())
			AND (a.auto_pause_on_expired IS NOT TRUE OR a.expires_at IS NULL OR a.expires_at > NOW())
				AND `+credentialsMatchSQL+`
			AND a.proxy_id IS NOT DISTINCT FROM $8
		RETURNING a.id
		)
		INSERT INTO scheduler_outbox (event_type, account_id, group_id, payload)
		SELECT $9, updated.id, NULL, NULL FROM updated
		`, args...)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return false, err
	}
	r.syncSchedulerAccountSnapshotDetached(ctx, id)
	return true, nil
}
