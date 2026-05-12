package probe

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/AliMousaviSoft/subjackal/internal/analyze"
	"github.com/AliMousaviSoft/subjackal/internal/model"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
}

func randomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

type HTTPProber struct {
	client *http.Client
}

func New(timeout time.Duration) *HTTPProber {
	return &HTTPProber{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

func (p *HTTPProber) Probe(ctx context.Context, sub *model.Subdomain) {
	if sub.Fingerprint == "" || sub.Score.CNAMEMatch == 0 {
		return
	}

	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, sub.Domain)
		body, status, err := p.get(ctx, url)
		if err != nil {
			continue
		}

		// check for takeover fingerprint in body
		fp := analyze.MatchHTTPBody(body)
		if fp != nil && fp.TakeoverPossible {
			sub.Score.HTTPMatch = 100
			sub.TakeoverPossible = true
			sub.Status = model.StatusVulnerable
			sub.Confidence = sub.Score.Level()
			sub.Note = fmt.Sprintf("CONFIRMED — %s fingerprint matched via HTTP (%s) — score: %d",
				fp.Name, scheme, sub.Score.Total())
			return
		}

		// page is live (2xx/3xx) → downgrade to ALIVE
		// this is the critical fix: active Shopify/Heroku/etc pages are not takeover candidates
		if status >= 200 && status < 400 {
			sub.Status = model.StatusAlive
			sub.TakeoverPossible = false
			sub.Note = fmt.Sprintf("CNAME → %s — page is live (%d), not a takeover candidate", sub.ServiceProvider, status)
			return
		}

		// 4xx/5xx that's NOT the takeover fingerprint — ambiguous, keep suspicious
		break
	}

	if sub.Status == model.StatusSuspicious {
		sub.Note += " [HTTP: no fingerprint match, manual verification needed]"
	}
}

func (p *HTTPProber) get(ctx context.Context, url string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}

	req.Header.Set("User-Agent", randomUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	n, _ := io.ReadFull(resp.Body, buf)
	return strings.ToLower(string(buf[:n])), resp.StatusCode, nil
}