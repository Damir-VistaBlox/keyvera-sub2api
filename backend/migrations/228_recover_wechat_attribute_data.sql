-- Recover wechat user attribute data orphaned by migration 019.
--
-- The migration runner (internal/repository/migrations_runner.go) executes a
-- migration file's full content as one transaction; it does not parse goose
-- "-- +goose Up" / "-- +goose Down" markers (see migrations/README.md).
-- 019_migrate_wechat_to_attributes.sql contains both an Up block (move
-- users.wechat into user_attribute_values, drop the column) and a Down block
-- (restore users.wechat, delete the migrated user_attribute_values rows,
-- soft-delete the "wechat" attribute definition). Both ran in every
-- environment, leaving user-submitted wechat contact info sitting in
-- users.wechat, a column ent/schema/user.go no longer declares and no
-- application code path reads or writes (see issue #26).
--
-- This migration finishes what 019 originally intended: restore the
-- attribute definition, re-copy any current non-empty users.wechat values
-- into user_attribute_values, then drop the column again.

-- Step 1: restore the "wechat" attribute definition. The partial unique
-- index on key only covers deleted_at IS NULL rows (see migration 018), so
-- un-deleting the row 019 soft-deleted is safe even if it still exists.
UPDATE user_attribute_definitions
SET deleted_at = NULL,
    updated_at = NOW()
WHERE key = 'wechat' AND deleted_at IS NOT NULL;

-- Defensive fallback in case some environment never had 019 create the row.
INSERT INTO user_attribute_definitions (key, name, description, type, options, required, validation, placeholder, display_order, enabled, created_at, updated_at)
SELECT 'wechat', '微信', '用户微信号', 'text', '[]'::jsonb, false, '{}'::jsonb, '请输入微信号', 0, true, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM user_attribute_definitions WHERE key = 'wechat' AND deleted_at IS NULL
);

-- Step 2: re-copy current non-empty users.wechat values into
-- user_attribute_values, skipping any user who already has a wechat value
-- recorded there.
INSERT INTO user_attribute_values (user_id, attribute_id, value, created_at, updated_at)
SELECT
    u.id,
    (SELECT id FROM user_attribute_definitions WHERE key = 'wechat' AND deleted_at IS NULL LIMIT 1),
    u.wechat,
    NOW(),
    NOW()
FROM users u
WHERE u.wechat IS NOT NULL
  AND u.wechat != ''
  AND u.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM user_attribute_values uav
      WHERE uav.user_id = u.id
        AND uav.attribute_id = (SELECT id FROM user_attribute_definitions WHERE key = 'wechat' AND deleted_at IS NULL LIMIT 1)
  );

-- Step 3: drop the now-redundant column again, matching ent/schema/user.go
-- (which has had no wechat field since migration 019 was authored).
ALTER TABLE users DROP COLUMN IF EXISTS wechat;
