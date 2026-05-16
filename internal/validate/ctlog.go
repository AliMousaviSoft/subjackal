package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type CTLogResult struct {
	Found      bool
	IssuedDate string
	Issuer     string
}

func CheckCTLog(ctx context.Context, domain string) CTLogResult {
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return CTLogResult{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return CTLogResult{}
	}
	defer resp.Body.Close()

	var entries []struct {
		NotBefore  string `json:"not_before"`
		IssuerName string `json:"issuer_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return CTLogResult{}
	}

	if len(entries) == 0 {
		return CTLogResult{Found: false}
	}

	// most recent cert
	latest := entries[0]
	date := ""
	if len(latest.NotBefore) >= 10 {
		date = latest.NotBefore[:10]
	}

	// extract CN from issuer
	issuer := latest.IssuerName
	for _, part := range []string{"Let's Encrypt", "DigiCert", "Sectigo", "GlobalSign", "Microsoft", "Amazon"} {
		if len(issuer) > 0 {
			issuer = part
			break
		}
	}

	return CTLogResult{
		Found:      true,
		IssuedDate: date,
		Issuer:     issuer,
	}
}