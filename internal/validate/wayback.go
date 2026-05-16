package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type WaybackResult struct {
	Found    bool
	LastSeen string
	Total    int
}

func CheckWayback(ctx context.Context, domain string) WaybackResult {
	url := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s&output=json&limit=5&fl=timestamp&fastLatest=true",
		domain,
	)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return WaybackResult{}
	}

	resp, err := client.Do(req)
	if err != nil {
		return WaybackResult{}
	}
	defer resp.Body.Close()

	var entries [][]string
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return WaybackResult{}
	}

	// first entry is header row ["timestamp"]
	if len(entries) <= 1 {
		return WaybackResult{Found: false}
	}

	// last entry has most recent timestamp
	last := entries[len(entries)-1]
	timestamp := ""
	if len(last) > 0 {
		raw := last[0]
		// format: 20231015123456 → 2023-10-15
		if len(raw) >= 8 {
			timestamp = fmt.Sprintf("%s-%s-%s", raw[0:4], raw[4:6], raw[6:8])
		}
	}

	return WaybackResult{
		Found:    true,
		LastSeen: timestamp,
		Total:    len(entries) - 1,
	}
}