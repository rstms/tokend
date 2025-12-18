package handler

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

const CONFIG_DATA = `
tokend:
  verbose: true
  cache_dir: testdata/cache
`

func initTestConfig(t *testing.T) {
	if !IsDir("testdata") {
		err := os.Mkdir("testdata", 0700)
		require.Nil(t, err)
	}
	configFile := filepath.Join("testdata", "config.yaml")
	if !IsFile(configFile) {
		err := os.WriteFile(configFile, []byte(CONFIG_DATA), 0600)
		require.Nil(t, err)
	}
	Init("tokend", Version, filepath.Join("testdata", "config.yaml"))
	require.NotEmpty(t, Version)
}
