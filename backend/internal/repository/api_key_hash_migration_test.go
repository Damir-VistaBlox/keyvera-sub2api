package repository

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/migrations"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyHashMigration_AuthCacheInvalidationUsesStorageAwareDigest(t *testing.T) {
	content, err := migrations.FS.ReadFile("229_api_key_hash_auth_cache_invalidation.sql")
	require.NoError(t, err)
	sqlText := string(content)

	require.Contains(t, sqlText, "api_key_auth_cache_key_from_storage")
	require.Contains(t, sqlText, "^sha256:([0-9a-f]{64})$")
	require.Contains(t, sqlText, "encode(sha256(convert_to(stored_key, 'UTF8')), 'hex')")
	require.Contains(t, sqlText, "SELECT api_key_auth_cache_key_from_storage(k.key)")
	require.Contains(t, sqlText, "OLD.allow_image_generation IS NOT DISTINCT FROM NEW.allow_image_generation")
	require.Contains(t, sqlText, "OLD.profit_control_enabled IS NOT DISTINCT FROM NEW.profit_control_enabled")
}
