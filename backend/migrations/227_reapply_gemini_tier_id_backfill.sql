-- Re-apply the tier_id backfill from 024_add_gemini_tier_id.sql.
--
-- 024's embedded "-- +goose Down" ran in the same transaction as its "-- +goose Up"
-- (this project's migration runner does not parse goose Up/Down markers -- see
-- migrations/README.md). Up set credentials->>'tier_id' = 'LEGACY' for qualifying
-- accounts; Down then unconditionally stripped tier_id from every gemini oauth
-- account that had one -- including the rows Up had just set, since Down's WHERE
-- clause (credentials ? 'tier_id') is broader than Up's (credentials->>'tier_id'
-- IS NULL AND ...). Net effect: no account ever ended up with tier_id='LEGACY',
-- and internal/service/account.go's GeminiTierID() (consumed by
-- gemini_messages_compat_service.go and gemini_quota.go for tier-aware
-- quota/compat handling) has seen an empty tier_id for these accounts ever
-- since. See GitHub issue #7.
--
-- This migration is 024's Up statement, unchanged, run again. It is idempotent
-- (same tier_id IS NULL guard) and safe to apply regardless of whether 024 or
-- this migration has run before. It cannot distinguish "wiped by 024's Down"
-- from "never set", so it re-backfills 'LEGACY' for every currently-qualifying
-- account rather than only the ones 024 originally touched -- the same
-- forward-only backfill semantics 024 itself used.

UPDATE accounts
SET credentials = jsonb_set(
    credentials,
    '{tier_id}',
    '"LEGACY"',
    true
)
WHERE platform = 'gemini'
  AND type = 'oauth'
  AND jsonb_typeof(credentials) = 'object'
  AND credentials->>'tier_id' IS NULL
  AND (
    credentials->>'oauth_type' = 'code_assist'
    OR (credentials->>'oauth_type' IS NULL AND credentials->>'project_id' IS NOT NULL)
  );
