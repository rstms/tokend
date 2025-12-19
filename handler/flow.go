package handler

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const FLOW_LIFETIME = 300 * time.Second

type Flow struct {
	Id           string
	LocalAddress string
	Code         string
	Created      time.Time
}

func NewFlow(localAddress string) (*Flow, error) {
	fid, err := NewId()
	if err != nil {
		return nil, Fatal(err)
	}
	flow := Flow{
		Id:           fid,
		LocalAddress: localAddress,
		Created:      time.Now(),
	}
	log.Printf("created flow: %s\n", FormatJSON(flow))
	return &flow, nil
}

func (f *Flow) IsExpired() bool {
	return time.Now().After(f.Created.Add(FLOW_LIFETIME))
}

func flowCacheDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", Fatal(err)
	}
	ViperSetDefault("cache_dir", filepath.Join(dir, "tokend"))
	cacheDir := filepath.Join(ViperGetString("cache_dir"), "flows")
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
	flowFile := filepath.Join(flowDir, flow.Id) + ".json"
	return flowFile, nil
}

func DeleteFlow(flow *Flow) error {
	log.Printf("deleting flow: %s\n", flow.Id)
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
	log.Printf("writing flow: %s\n", flow.Id)
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

func ReadFlow(id string) (*Flow, error) {
	flowDir, err := flowCacheDir()
	flowFile := filepath.Join(flowDir, id+".json")
	data, err := os.ReadFile(flowFile)
	if err != nil {
		return nil, Fatal(err)
	}
	var flow Flow
	err = json.Unmarshal(data, &flow)
	if err != nil {
		return nil, Fatal(err)
	}
	log.Printf("read flow: %s\n", flow.Id)
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

func ListFlowIds() ([]string, error) {
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
	ids, err := ListFlowIds()
	if err != nil {
		return nil, Fatal(err)
	}
	flows := make(map[string]*Flow)
	for _, id := range ids {
		flow, err := ReadFlow(id)
		if err != nil {
			return nil, Fatal(err)
		}
		flows[id] = flow
	}
	return flows, nil
}
