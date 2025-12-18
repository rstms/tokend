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
	data, err := os.ReadFile(filepath.Join("testdata", "token.json"))
	require.Nil(t, err)
	var tokenMap map[string]any
	err = json.Unmarshal(data, &tokenMap)
	require.Nil(t, err)
	return tokenMap
}

func TestDecodeJWT(t *testing.T) {
	data := initTokenData(t)
	log.Printf("raw: %v\n", data["id_token"])
	jwt, err := DecodeJWT(data["id_token"].(string))
	require.Nil(t, err)
	log.Printf("decoded: %s\n", FormatJSON(jwt))
}

func TestDecodeToken(t *testing.T) {
	data := initTokenData(t)
	token, err := NewToken(data)
	require.Nil(t, err)
	log.Printf("token: %s\n", FormatJSON(token))
}
