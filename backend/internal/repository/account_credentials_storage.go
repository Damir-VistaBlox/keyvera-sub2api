package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

const (
	accountCredentialsCiphertextKey = "_sub2api_credentials_ciphertext"
	accountCredentialsEncryptedKey  = "_sub2api_credentials_encrypted"
	accountCredentialsIndexesKey    = "_sub2api_credentials_indexes"
	accountCredentialsSHA256Key     = "_sub2api_credentials_sha256"
	accountCredentialsVersionKey    = "_sub2api_credentials_version"
)

func (r *accountRepository) encryptCredentialsForStorage(credentials map[string]any) (map[string]any, error) {
	normalized := normalizeJSONMap(credentials)
	if r == nil || r.encryptor == nil || len(normalized) == 0 {
		return copyJSONMap(normalized), nil
	}
	plain, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	ciphertext, err := r.encryptor.Encrypt(string(plain))
	if err != nil {
		return nil, fmt.Errorf("encrypt account credentials: %w", err)
	}
	return map[string]any{
		accountCredentialsEncryptedKey:  true,
		accountCredentialsVersionKey:    1,
		accountCredentialsCiphertextKey: ciphertext,
		accountCredentialsSHA256Key:     sha256Hex(plain),
		accountCredentialsIndexesKey:    accountCredentialIndexes(normalized),
	}, nil
}

func (r *accountRepository) decryptCredentialsFromStorage(stored map[string]any) (map[string]any, error) {
	if !accountCredentialsStorageEncrypted(stored) {
		return copyJSONMap(stored), nil
	}
	if r == nil || r.encryptor == nil {
		return nil, fmt.Errorf("account credentials are encrypted but no decryptor is configured")
	}
	ciphertext, _ := stored[accountCredentialsCiphertextKey].(string)
	if strings.TrimSpace(ciphertext) == "" {
		return nil, fmt.Errorf("encrypted account credentials missing ciphertext")
	}
	plain, err := r.encryptor.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt account credentials: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(plain), &out); err != nil {
		return nil, fmt.Errorf("decode account credentials: %w", err)
	}
	return normalizeJSONMap(out), nil
}

func (r *accountRepository) accountEntityToService(m *dbent.Account) (*service.Account, error) {
	if m == nil {
		return nil, nil
	}
	credentials, err := r.decryptCredentialsFromStorage(m.Credentials)
	if err != nil {
		return nil, err
	}
	return accountEntityToServiceWithCredentials(m, credentials), nil
}

func (r *accountRepository) credentialsStorageJSONAndDigest(credentials map[string]any) (storedJSON string, plainDigest string, err error) {
	normalized := normalizeJSONMap(credentials)
	_, digest, err := credentialsPlaintextJSONAndDigest(normalized)
	if err != nil {
		return "", "", err
	}
	stored, err := r.encryptCredentialsForStorage(normalized)
	if err != nil {
		return "", "", err
	}
	payload, err := json.Marshal(stored)
	if err != nil {
		return "", "", err
	}
	return string(payload), digest, nil
}

func credentialsPlaintextJSONAndDigest(credentials map[string]any) (plainJSON string, plainDigest string, err error) {
	plain, err := json.Marshal(normalizeJSONMap(credentials))
	if err != nil {
		return "", "", err
	}
	return string(plain), sha256Hex(plain), nil
}

func accountCredentialsStorageEncrypted(stored map[string]any) bool {
	encrypted, _ := stored[accountCredentialsEncryptedKey].(bool)
	if encrypted {
		return true
	}
	_, hasCiphertext := stored[accountCredentialsCiphertextKey]
	return hasCiphertext
}

func accountCredentialIndexes(credentials map[string]any) map[string]any {
	indexes := make(map[string]any, 4)
	apiKey := credentialString(credentials, "api_key")
	if apiKey != "" {
		indexes["api_key_sha256"] = credentialSHA256String(apiKey)
		indexes["api_key_present"] = true
	}
	if baseURL := credentialString(credentials, "base_url"); baseURL != "" {
		indexes["base_url"] = baseURL
	}
	refreshToken := strings.TrimSpace(credentialString(credentials, "refresh_token"))
	indexes["refresh_token_present"] = refreshToken != ""
	return indexes
}

func credentialString(credentials map[string]any, key string) string {
	if credentials == nil {
		return ""
	}
	value, ok := credentials[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

func credentialSHA256String(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func accountCredentialsMatchSQL(column, plaintextJSONArg, digestArg string) string {
	return "((" + column + " ->> '" + accountCredentialsSHA256Key + "') = " + digestArg +
		" OR (NOT (" + column + " ? '" + accountCredentialsCiphertextKey + "') AND " + column + " = " + plaintextJSONArg + "::jsonb))"
}

func accountCredentialsRefreshTokenAbsentSQL(column string) string {
	return "COALESCE(((" + column + " -> '" + accountCredentialsIndexesKey + "' ->> 'refresh_token_present')::boolean), NULLIF(BTRIM(" + column + "->>'refresh_token'), '') IS NOT NULL, false) IS FALSE"
}

func accountCredentialsAPIKeyMatchesSQL(column, apiKeyArg, apiKeyHashArg string) string {
	return "(((" + column + " -> '" + accountCredentialsIndexesKey + "' ->> 'api_key_sha256') = " + apiKeyHashArg + ") OR (NOT (" + column + " ? '" + accountCredentialsCiphertextKey + "') AND " + column + "->>'api_key' = " + apiKeyArg + "))"
}

func accountCredentialsBaseURLSQL(column string) string {
	return "COALESCE(" + column + " -> '" + accountCredentialsIndexesKey + "' ->> 'base_url', " + column + " ->> 'base_url')"
}

func accountCredentialsHasAPIKeySQL(column string) string {
	return "COALESCE(((" + column + " -> '" + accountCredentialsIndexesKey + "' ->> 'api_key_present')::boolean), jsonb_typeof(" + column + " -> 'api_key') = 'string', false)"
}
