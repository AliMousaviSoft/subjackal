package analyze

import (
	_ "embed"
	"encoding/json"
	"os"
	"strings"
)

//go:embed fingerprints.json
var fingerprintData []byte

type Fingerprint struct {
	Name             string   `json:"name"`
	CNAMEPatterns    []string `json:"cname_patterns"`
	HTTPFingerprint  string   `json:"http_fingerprint"`
	NXDOMAINOnly     bool     `json:"nxdomain_only"`
	Status           string   `json:"status"`  // vulnerable, not_vulnerable, edge_case
	StatusCodes      []int    `json:"status_codes"`
	Confidence       string   `json:"confidence"`
	TakeoverPossible bool     `json:"takeover_possible"`
	Discussion       string   `json:"discussion"`
}

type FingerprintDB struct {
	Services []Fingerprint `json:"services"`
}

var db *FingerprintDB

func init() {
	db = &FingerprintDB{}
	if err := json.Unmarshal(fingerprintData, db); err != nil {
		panic("failed to load fingerprints.json: " + err.Error())
	}
}

// LoadFingerprintsFromFile replaces the embedded DB with a custom file
func LoadFingerprintsFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	custom := &FingerprintDB{}
	if err := json.Unmarshal(data, custom); err != nil {
		return err
	}
	// merge: custom takes priority, append new entries
	existing := make(map[string]bool)
	for _, s := range custom.Services {
		existing[strings.ToLower(s.Name)] = true
	}
	for _, s := range db.Services {
		if !existing[strings.ToLower(s.Name)] {
			custom.Services = append(custom.Services, s)
		}
	}
	db = custom
	return nil
}

func MatchCNAME(cnameTarget string) *Fingerprint {
	cnameTarget = strings.ToLower(cnameTarget)
	for i := range db.Services {
		fp := &db.Services[i]
		for _, pattern := range fp.CNAMEPatterns {
			if strings.HasSuffix(cnameTarget, strings.ToLower(pattern)) {
				return fp
			}
		}
	}
	return nil
}

func MatchHTTPBody(body string) *Fingerprint {
	body = strings.ToLower(body)
	for i := range db.Services {
		fp := &db.Services[i]
		if fp.HTTPFingerprint == "" {
			continue
		}
		if strings.Contains(body, strings.ToLower(fp.HTTPFingerprint)) {
			return fp
		}
	}
	return nil
}