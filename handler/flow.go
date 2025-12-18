package handler

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type Flow struct {
	Local        string
	Gmail        string
	JWT          string
	AuthToken    string
	RefreshToken string
	Nonce        *Nonce
	Code         string
	Token        *Token
}

func NewFlow() (*Flow, error) {
	nonce, err := NewNonce()
	if err != nil {
		return nil, Fatal(err)
	}
	flow := Flow{
		Nonce: nonce,
	}
	return &flow, nil
}

func flowCacheDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", Fatal(err)
	}
	ViperSetDefault("cache_dir", filepath.Join(dir, "tokend"))
	cacheDir := ViperGetString("cache_dir")
	if !IsDir(cacheDir) {
		err := os.MkdirAll(cacheDir, 0700)
		if err != nil {
			return "", Fatal(err)
		}
	}
	err = os.Chmod(cacheDir, 0700)
	if err != nil {
		return "", Fatal(err)
	}
	return cacheDir, nil
}

func flowFilename(flow *Flow) (string, error) {
	flowDir, err := flowCacheDir()
	if err != nil {
		return "", Fatal(err)
	}
	flowFile := filepath.Join(flowDir, flow.Nonce.Text) + ".json"
	return flowFile, nil
}

func DeleteFlow(flow *Flow) error {
	flowFile, err := flowFilename(flow)
	if err != nil {
		return Fatal(err)
	}
	if IsFile(flowFile) {

		log.Printf("deleting %s\n", flowFile)
		err := os.Remove(flowFile)
		if err != nil {
			return Fatal(err)
		}
	} else {
		log.Printf("DeleteFlow: %s is not a file\n", flowFile)
	}
	return nil
}

func WriteFlow(flow *Flow) error {
	flowFile, err := flowFilename(flow)
	if err != nil {
		return Fatal(err)
	}

	data, err := json.Marshal(flow)
	if err != nil {
		return Fatal(err)
	}

	err = os.WriteFile(flowFile, data, 0600)
	if err != nil {
		return Fatal(err)
	}
	return nil
}

func ReadFlow(state string) (*Flow, error) {
	flowDir, err := flowCacheDir()
	flowFile := filepath.Join(flowDir, state+".json")
	data, err := os.ReadFile(flowFile)
	if err != nil {
		return nil, Fatal(err)
	}
	var flow Flow
	err = json.Unmarshal(data, &flow)
	if err != nil {
		return nil, Fatal(err)
	}
	return &flow, nil
}

func WriteFlowMap(flows map[string]*Flow) error {
	for _, flow := range flows {
		err := WriteFlow(flow)
		if err != nil {
			return Fatal(err)
		}
	}
	return nil
}

func ListFlowStates() ([]string, error) {
	flowDir, err := flowCacheDir()
	if err != nil {
		return nil, Fatal(err)
	}
	entries, err := os.ReadDir(flowDir)
	if err != nil {
		return nil, Fatal(err)
	}
	states := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.Type().IsRegular() && strings.HasSuffix(name, ".json") {
			state := strings.TrimSuffix(name, ".json")
			states = append(states, state)
		}
	}
	return states, nil
}

func ReadFlowMap() (map[string]*Flow, error) {
	states, err := ListFlowStates()
	if err != nil {
		return nil, Fatal(err)
	}
	flows := make(map[string]*Flow)
	for _, state := range states {
		flow, err := ReadFlow(state)
		if err != nil {
			return nil, Fatal(err)
		}
		flows[state] = flow
	}
	return flows, nil
}
