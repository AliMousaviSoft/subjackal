package resolve

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var DefaultResolvers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
	"9.9.9.9:53",
	"129.250.35.251:53",
	"208.67.222.222:53",
}

type cacheEntry struct {
	msg *dns.Msg
	exp time.Time
}

type Resolver struct {
	servers []string
	timeout time.Duration
	retries int
	client  *dns.Client
	cache   sync.Map // key: "fqdn:qtype" → cacheEntry
}

func New(servers []string, timeout time.Duration, retries int) *Resolver {
	merged := make([]string, 0, len(DefaultResolvers)+len(servers))
	merged = append(merged, DefaultResolvers...)
	for _, s := range servers {
		if !strings.Contains(s, ":") {
			s = s + ":53"
		}
		merged = append(merged, s)
	}
	return &Resolver{
		servers: merged,
		timeout: timeout,
		retries: retries,
		client:  &dns.Client{Timeout: timeout, Net: "udp"},
	}
}

func (r *Resolver) cacheKey(fqdn string, qtype uint16) string {
	return fmt.Sprintf("%s:%d", fqdn, qtype)
}

func (r *Resolver) pickServer() string {
	return r.servers[rand.Intn(len(r.servers))]
}

func (r *Resolver) query(ctx context.Context, fqdn string, qtype uint16) (*dns.Msg, error) {
	key := r.cacheKey(fqdn, qtype)

	// check cache
	if v, ok := r.cache.Load(key); ok {
		entry := v.(cacheEntry)
		if time.Now().Before(entry.exp) {
			return entry.msg, nil
		}
		r.cache.Delete(key)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), qtype)
	m.RecursionDesired = true

	var (
		resp *dns.Msg
		err  error
	)

	// try all resolvers, not just random pick — for cache accuracy
	servers := make([]string, len(r.servers))
	copy(servers, r.servers)
	rand.Shuffle(len(servers), func(i, j int) { servers[i], servers[j] = servers[j], servers[i] })

	for i := 0; i < r.retries; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		server := servers[i%len(servers)]
		resp, _, err = r.client.Exchange(m, server)
		if err == nil {
			// cache for 60 seconds
			r.cache.Store(key, cacheEntry{msg: resp, exp: time.Now().Add(60 * time.Second)})
			return resp, nil
		}
	}
	return nil, fmt.Errorf("query failed after %d retries: %w", r.retries, err)
}

func (r *Resolver) LookupA(ctx context.Context, host string) ([]string, error) {
	resp, err := r.query(ctx, host, dns.TypeA)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips, nil
}

func (r *Resolver) LookupAAAA(ctx context.Context, host string) ([]string, error) {
	resp, err := r.query(ctx, host, dns.TypeAAAA)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, rr := range resp.Answer {
		if aaaa, ok := rr.(*dns.AAAA); ok {
			ips = append(ips, aaaa.AAAA.String())
		}
	}
	return ips, nil
}

func (r *Resolver) LookupNS(ctx context.Context, host string) ([]string, error) {
	resp, err := r.query(ctx, host, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	var ns []string
	for _, rr := range resp.Answer {
		if n, ok := rr.(*dns.NS); ok {
			ns = append(ns, n.Ns)
		}
	}
	return ns, nil
}

func (r *Resolver) LookupMX(ctx context.Context, host string) ([]string, error) {
	resp, err := r.query(ctx, host, dns.TypeMX)
	if err != nil {
		return nil, err
	}
	var mx []string
	for _, rr := range resp.Answer {
		if m, ok := rr.(*dns.MX); ok {
			mx = append(mx, fmt.Sprintf("%d %s", m.Preference, m.Mx))
		}
	}
	return mx, nil
}

// IsNXDOMAIN retries across multiple resolvers before confirming NXDOMAIN
// This prevents false positives from a single resolver being down
func (r *Resolver) IsNXDOMAIN(ctx context.Context, host string) (bool, error) {
	nxCount := 0
	total := min(len(r.servers), 3) // check up to 3 different resolvers

	servers := make([]string, len(r.servers))
	copy(servers, r.servers)
	rand.Shuffle(len(servers), func(i, j int) { servers[i], servers[j] = servers[j], servers[i] })

	for i := 0; i < total; i++ {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), dns.TypeA)
		m.RecursionDesired = true

		resp, _, err := r.client.Exchange(m, servers[i])
		if err != nil {
			continue
		}
		if resp.Rcode == dns.RcodeNameError {
			nxCount++
		}
	}

	// only confirm NXDOMAIN if majority agree
	return nxCount >= 2, nil
}

func (r *Resolver) DetectWildcard(ctx context.Context, domain string) (bool, string) {
	probe := fmt.Sprintf("%s.%s", randomHex(12), domain)
	ips, err := r.LookupA(ctx, probe)
	if err != nil || len(ips) == 0 {
		return false, ""
	}
	return true, ips[0]
}

func (r *Resolver) ResolveCNAMEChain(ctx context.Context, host string) (chain []string, final string, finalIPs []string, err error) {
	current := host
	seen := make(map[string]bool)

	for {
		if seen[current] {
			break
		}
		seen[current] = true

		resp, err := r.query(ctx, current, dns.TypeCNAME)
		if err != nil {
			break
		}

		var next string
		for _, rr := range resp.Answer {
			if cname, ok := rr.(*dns.CNAME); ok {
				next = cname.Target
				break
			}
		}
		if next == "" {
			break
		}

		chain = append(chain, next)
		current = next

		select {
		case <-ctx.Done():
			return chain, current, nil, ctx.Err()
		default:
		}
	}

	final = strings.TrimSuffix(current, ".")

	// always resolve final hop A records — this is the critical fix
	// Azure/Cloudflare chains end with an A record, not another CNAME
	ips, _ := r.LookupA(ctx, final)
	finalIPs = ips

	return chain, final, finalIPs, nil
}

func IsReachable(host string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", host), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func randomHex(n int) string {
	const chars = "abcdef0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}