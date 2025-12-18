package handler

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func initTokenData(t *testing.T) map[string]any {
	initTestConfig(t)
	testTokenFile := filepath.Join("testdata", "token.json")
	var tokenMap map[string]any
	if IsFile(testTokenFile) {
		data, err := os.ReadFile(testTokenFile)
		require.Nil(t, err)
		err = json.Unmarshal(data, &tokenMap)
		require.Nil(t, err)
	} else {
		log.Printf("WARNING: handler/testdata/token.json not found; skipping token decode tests")
	}
	return tokenMap
}

func TestDecodeJWT(t *testing.T) {
	data := initTokenData(t)
	if len(data) > 0 {
		log.Printf("raw: %v\n", data["id_token"])
		jwt, err := DecodeJWT(data["id_token"].(string))
		require.Nil(t, err)
		log.Printf("decoded: %s\n", FormatJSON(jwt))
	}
}

func TestDecodeToken(t *testing.T) {
	data := initTokenData(t)
	if len(data) > 0 {
		token, err := NewToken(data)
		require.Nil(t, err)
		log.Printf("token: %s\n", FormatJSON(token))
	}
}
