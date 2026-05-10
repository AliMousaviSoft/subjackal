package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/AliMousaviSoft/subjackal/internal/analyze"
	"github.com/AliMousaviSoft/subjackal/internal/model"
)

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
	if sub.Fingerprint == "" {
		return
	}
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, sub.Domain)
		body, _, err := p.get(ctx, url)
		if err != nil {
			continue
		}
		fp := analyze.MatchHTTPBody(body)
		if fp != nil && fp.TakeoverPossible {
			sub.TakeoverPossible = true
			sub.Status = model.StatusVulnerable
			sub.Confidence = model.ConfidenceHigh
			sub.Note = fmt.Sprintf("CONFIRMED — %s fingerprint matched via HTTP (%s)", fp.Name, scheme)
			return
		}
	}
	if sub.Status == model.StatusSuspicious {
		sub.Note += " [HTTP probe: no fingerprint match]"
	}
}

func (p *HTTPProber) get(ctx context.Context, url string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "subjackal/1.0")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := io.ReadFull(resp.Body, buf)
	return strings.ToLower(string(buf[:n])), resp.StatusCode, nil
}
