package handler

import (
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func initFlowTestConfig(t *testing.T) {
	initTestConfig(t)
	err := os.RemoveAll(filepath.Join("testdata", "cache"))
	require.Nil(t, err)
}

func TestFlowNew(t *testing.T) {
	initFlowTestConfig(t)
	log.Printf("ViperConfig: %s\n", FormatJSON(viper.AllSettings()))
	require.Equal(t, ViperGetString("cache_dir"), filepath.Join("testdata", "cache"))
	flow, err := NewFlow()
	require.Nil(t, err)
	log.Printf("flow: %s\n", FormatJSON(flow))
}

func TestFlowStorage(t *testing.T) {
	initFlowTestConfig(t)
	flows := map[string]*Flow{}
	flow1, err := NewFlow()
	require.Nil(t, err)
	flows[flow1.Nonce.Text] = flow1
	flow2, err := NewFlow()
	require.Nil(t, err)
	flows[flow2.Nonce.Text] = flow2
	log.Printf("flows: %s\n", FormatJSON(flows))

	err = WriteFlowMap(flows)
	require.Nil(t, err)

	readBack, err := ReadFlowMap()
	require.Nil(t, err)

	require.Equal(t, len(flows), len(readBack))

	for state, flow := range flows {
		rbf, ok := readBack[state]
		require.True(t, ok)
		log.Printf("%s\n", FormatJSON(flow))
		log.Printf("%s\n", FormatJSON(rbf))
	}
}
