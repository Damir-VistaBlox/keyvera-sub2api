package service

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	APIKeyStorageHashPrefix = "sha256:"
	apiKeySHA256HexLength   = 64
)

func HashAPIKeyForStorage(key string) string {
	return APIKeyStorageHashPrefix + apiKeySHA256Hex(key)
}

func APIKeyStorageLookupValues(key string) []string {
	hashed := HashAPIKeyForStorage(key)
	if key == hashed {
		return []string{hashed}
	}
	return []string{hashed, key}
}

func IsHashedAPIKeyStorageValue(value string) bool {
	digest, ok := strings.CutPrefix(value, APIKeyStorageHashPrefix)
	if !ok || len(digest) != apiKeySHA256HexLength {
		return false
	}
	for _, r := range digest {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func APIKeyAuthCacheKeyFromCredentialOrStorageValue(key string) string {
	if digest, ok := strings.CutPrefix(key, APIKeyStorageHashPrefix); ok && IsHashedAPIKeyStorageValue(key) {
		return digest
	}
	return apiKeySHA256Hex(key)
}

func RedactAPIKeyIfStoredHash(key string) string {
	if IsHashedAPIKeyStorageValue(key) {
		return ""
	}
	return key
}

func apiKeySHA256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
