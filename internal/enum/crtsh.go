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
	Debug  bool
}

func NewCrtSh() *CrtSh {
	return &CrtSh{client: &http.Client{Timeout: 60 * time.Second}}
}

func (c *CrtSh) Name() string { return "crt.sh" }

func (c *CrtSh) Enumerate(ctx context.Context, domain string) (<-chan string, error) {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		url := fmt.Sprintf(crtshURL, domain)

		var resp *http.Response
		var err error

		for attempt := 0; attempt < 6; attempt++ {
			req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if e != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "application/json")

			resp, err = c.client.Do(req)
			if err == nil && resp.StatusCode == 200 {
				break
			}

			status := 0
			if resp != nil {
				status = resp.StatusCode
				resp.Body.Close()
			}

			wait := time.Duration(1<<uint(attempt+1)) * time.Second
			if c.Debug {
				fmt.Printf("[crt.sh] status %d, retrying in %s...\n", status, wait)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}

		if err != nil || resp == nil || resp.StatusCode != 200 {
			if c.Debug {
				fmt.Printf("[crt.sh] failed after retries\n")
			}
			return
		}
		defer resp.Body.Close()

		var entries []struct {
			NameValue string `json:"name_value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			if c.Debug {
				fmt.Printf("[crt.sh] decode error: %v\n", err)
			}
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