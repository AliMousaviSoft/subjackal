package analyze

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed fingerprints.json
var fingerprintData []byte

type Fingerprint struct {
	Name             string   `json:"name"`
	CNAMEPatterns    []string `json:"cname_patterns"`
	HTTPFingerprint  string   `json:"http_fingerprint"`
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
