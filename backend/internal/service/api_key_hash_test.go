package service

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPIKeyStorageHashAndAuthCacheKey(t *testing.T) {
	raw := "sk-storage-hash-test"
	sum := sha256.Sum256([]byte(raw))
	digest := hex.EncodeToString(sum[:])

	stored := HashAPIKeyForStorage(raw)
	require.Equal(t, APIKeyStorageHashPrefix+digest, stored)
	require.True(t, IsHashedAPIKeyStorageValue(stored))
	require.Equal(t, digest, APIKeyAuthCacheKeyFromCredentialOrStorageValue(raw))
	require.Equal(t, digest, APIKeyAuthCacheKeyFromCredentialOrStorageValue(stored))
	require.Equal(t, "", RedactAPIKeyIfStoredHash(stored))
	require.Equal(t, raw, RedactAPIKeyIfStoredHash(raw))
}

func TestIsHashedAPIKeyStorageValueRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{
		"",
		"sha256:",
		"sha256:abc",
		"sha256:" + "000000000000000000000000000000000000000000000000000000000000000g",
		"sha512:0000000000000000000000000000000000000000000000000000000000000000",
	} {
		require.False(t, IsHashedAPIKeyStorageValue(value), value)
	}
}
