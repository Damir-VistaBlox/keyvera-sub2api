package dto

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyFromService_RedactsStoredHash(t *testing.T) {
	out := APIKeyFromService(&service.APIKey{
		ID:  1,
		Key: service.HashAPIKeyForStorage("sk-redact-me"),
	})

	require.NotNil(t, out)
	require.Empty(t, out.Key)
}
