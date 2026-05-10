package resolve

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var DefaultResolvers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
	"9.9.9.9:53",
}

type Resolver struct {
	servers []string
	timeout time.Duration
	retries int
	client  *dns.Client
}

func New(servers []string, timeout time.Duration, retries int) *Resolver {
	if len(servers) == 0 {
		servers = DefaultResolvers
	}
	return &Resolver{
		servers: servers,
		timeout: timeout,
		retries: retries,
		client:  &dns.Client{Timeout: timeout, Net: "udp"},
	}
}

func (r *Resolver) pickServer() string {
	return r.servers[rand.Intn(len(r.servers))]
}

func (r *Resolver) query(ctx context.Context, fqdn string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), qtype)
	m.RecursionDesired = true
	var (
		resp *dns.Msg
		err  error
	)
	for i := 0; i < r.retries; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		resp, _, err = r.client.Exchange(m, r.pickServer())
		if err == nil {
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

func (r *Resolver) IsNXDOMAIN(ctx context.Context, host string) (bool, error) {
	resp, err := r.query(ctx, host, dns.TypeA)
	if err != nil {
		return false, err
	}
	return resp.Rcode == dns.RcodeNameError, nil
}

func (r *Resolver) DetectWildcard(ctx context.Context, domain string) (bool, string) {
	probe := fmt.Sprintf("%s.%s", randomHex(12), domain)
	ips, err := r.LookupA(ctx, probe)
	if err != nil || len(ips) == 0 {
		return false, ""
	}
	return true, ips[0]
}

func (r *Resolver) ResolveCNAMEChain(ctx context.Context, host string) (chain []string, final string, err error) {
	current := host
	seen := make(map[string]bool)
	for {
		if seen[current] {
			break
		}
		seen[current] = true
		resp, err := r.query(ctx, current, dns.TypeCNAME)
		if err != nil {
			return chain, current, nil
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
			return chain, current, ctx.Err()
		default:
		}
	}
	final = strings.TrimSuffix(current, ".")
	return chain, final, nil
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
