package enum

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const crtshURL = "https://crt.sh/?q=%%25.%s&output=json"

type CrtSh struct {
	client *http.Client
}

func NewCrtSh() *CrtSh {
	return &CrtSh{client: &http.Client{Timeout: 30 * time.Second}}
}

func (c *CrtSh) Name() string { return "crt.sh" }

func (c *CrtSh) Enumerate(ctx context.Context, domain string) (<-chan string, error) {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		url := fmt.Sprintf(crtshURL, domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return
		}
		var resp *http.Response
		for attempt := 0; attempt < 3; attempt++ {
			resp, err = c.client.Do(req)
			if err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(attempt+1) * 2 * time.Second):
			}
		}
		if err != nil || resp == nil {
			return
		}
		defer resp.Body.Close()
		var entries []struct {
			NameValue string `json:"name_value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			return
		}
		seen := make(map[string]bool)
		for _, e := range entries {
			for _, name := range strings.Split(e.NameValue, "\n") {
				name = strings.ToLower(strings.TrimSpace(name))
				if strings.HasPrefix(name, "*.") {
					continue
				}
				if !strings.HasSuffix(name, "."+domain) && name != domain {
					continue
				}
				if seen[name] {
					continue
				}
				seen[name] = true
				select {
				case <-ctx.Done():
					return
				case out <- name:
				}
			}
		}
	}()
	return out, nil
}
