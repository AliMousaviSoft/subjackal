package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type CTLogResult struct {
	Found      bool
	IssuedDate string
	Issuer     string
	Total      int
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

	latest := entries[0]

	// extract CN= value from issuer string
	// e.g. "C=US, O=Let's Encrypt, CN=R11" → "Let's Encrypt"
	issuer := extractIssuerOrg(latest.IssuerName)

	date := ""
	if len(latest.NotBefore) >= 10 {
		date = latest.NotBefore[:10]
	}

	return CTLogResult{
		Found:      true,
		IssuedDate: date,
		Issuer:     issuer,
		Total:      len(entries),
	}
}

// extractIssuerOrg pulls O= field from issuer DN string
// e.g. "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1" → "DigiCert Inc"
func extractIssuerOrg(issuerDN string) string {
	parts := strings.Split(issuerDN, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "O=") {
			return strings.TrimPrefix(part, "O=")
		}
	}
	// fallback: return CN= if no O=
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return issuerDN
}