package handler

import (
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func initTestConfig(t *testing.T) {
	Init("tokend", Version, filepath.Join("testdata", "config.yaml"))
	require.NotEmpty(t, Version)
}
