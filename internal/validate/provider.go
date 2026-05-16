package validate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ProviderResult struct {
	Reclaimable bool
	HTTPStatus  int
	Body        string
	Reason      string
}

// provider-specific reclaimability checks
var reclaimablePatterns = map[string][]string{
	"Microsoft Azure": {
		"404 web site not found",
		"the resource you are looking for has been removed",
		"no web site is configured at this address",
	},
	"GitHub Pages": {
		"there isn't a github pages site here",
	},
	"Heroku": {
		"no such app",
		"heroku | no such app",
	},
	"Shopify": {
		"sorry, this shop is currently unavailable",
	},
	"AWS/S3": {
		"nosuchbucket",
		"the specified bucket does not exist",
	},
	"Netlify": {
		"not found - request id",
	},
	"Vercel": {
		"deployment_not_found",
		"the deployment you are trying to access does not exist",
	},
	"Ghost": {
		"site unavailable",
	},
	"Surge.sh": {
		"project not found",
	},
}

// reserved patterns — these mean provider is blocking takeover
var reservedPatterns = map[string][]string{
	"Microsoft Azure": {
		"microsoft corporation",
		"this subscription has been disabled",
		"this resource does not exist",
	},
}

func CheckProvider(ctx context.Context, domain, provider string) ProviderResult {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	var body string
	var status int

	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		buf := make([]byte, 8192)
		n, _ := io.ReadFull(resp.Body, buf)
		body = strings.ToLower(string(buf[:n]))
		status = resp.StatusCode
		break
	}

	if body == "" {
		return ProviderResult{
			Reclaimable: false,
			HTTPStatus:  status,
			Reason:      "could not reach endpoint",
		}
	}

	// check reserved first (takes priority)
	if patterns, ok := reservedPatterns[provider]; ok {
		for _, pattern := range patterns {
			if strings.Contains(body, strings.ToLower(pattern)) {
				return ProviderResult{
					Reclaimable: false,
					HTTPStatus:  status,
					Body:        body[:min(200, len(body))],
					Reason:      "provider has reserved this resource",
				}
			}
		}
	}

	// check reclaimable patterns
	if patterns, ok := reclaimablePatterns[provider]; ok {
		for _, pattern := range patterns {
			if strings.Contains(body, strings.ToLower(pattern)) {
				return ProviderResult{
					Reclaimable: true,
					HTTPStatus:  status,
					Body:        body[:min(200, len(body))],
					Reason:      "matched reclaimable pattern: " + pattern,
				}
			}
		}
	}

	// 2xx means page is live — not reclaimable
	if status >= 200 && status < 400 {
		return ProviderResult{
			Reclaimable: false,
			HTTPStatus:  status,
			Reason:      fmt.Sprintf("endpoint is live (%d) — not a takeover candidate", status),
		}
	}

	return ProviderResult{
		Reclaimable: false,
		HTTPStatus:  status,
		Reason:      fmt.Sprintf("no reclaimable pattern matched (HTTP %d)", status),
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}