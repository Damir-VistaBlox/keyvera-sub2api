package repository

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type accountCredentialTestEncryptor struct{}

func (accountCredentialTestEncryptor) Encrypt(plaintext string) (string, error) {
	return "cipher:" + plaintext, nil
}

func (accountCredentialTestEncryptor) Decrypt(ciphertext string) (string, error) {
	return strings.TrimPrefix(ciphertext, "cipher:"), nil
}

func TestAccountCredentialsStorageEncryptsAndDecrypts(t *testing.T) {
	repo := newAccountRepositoryWithSQL(nil, nil, nil, accountCredentialTestEncryptor{})
	plain := map[string]any{
		"api_key":       "sk-secret",
		"base_url":      "https://ollama.com/v1",
		"refresh_token": "refresh-secret",
	}

	stored, err := repo.encryptCredentialsForStorage(plain)
	require.NoError(t, err)
	require.True(t, accountCredentialsStorageEncrypted(stored))
	require.NotContains(t, stored, "api_key")
	require.NotContains(t, stored, "refresh_token")
	require.NotEmpty(t, stored[accountCredentialsCiphertextKey])
	require.NotEmpty(t, stored[accountCredentialsSHA256Key])

	indexes, ok := stored[accountCredentialsIndexesKey].(map[string]any)
	require.True(t, ok)
	require.Equal(t, credentialSHA256String("sk-secret"), indexes["api_key_sha256"])
	require.Equal(t, "https://ollama.com/v1", indexes["base_url"])
	require.Equal(t, true, indexes["refresh_token_present"])

	decrypted, err := repo.decryptCredentialsFromStorage(stored)
	require.NoError(t, err)
	require.Equal(t, plain["api_key"], decrypted["api_key"])
	require.Equal(t, plain["refresh_token"], decrypted["refresh_token"])
}

func TestAccountCredentialsStorageReadsLegacyPlaintext(t *testing.T) {
	repo := newAccountRepositoryWithSQL(nil, nil, nil, accountCredentialTestEncryptor{})
	legacy := map[string]any{"api_key": "sk-legacy"}

	decrypted, err := repo.decryptCredentialsFromStorage(legacy)
	require.NoError(t, err)
	require.Equal(t, "sk-legacy", decrypted["api_key"])
}
