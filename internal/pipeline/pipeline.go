package pipeline

import (
	"context"
	"sync"

	"github.com/AliMousaviSoft/subjackal/internal/analyze"
	"github.com/AliMousaviSoft/subjackal/internal/enum"
	"github.com/AliMousaviSoft/subjackal/internal/model"
	"github.com/AliMousaviSoft/subjackal/internal/probe"
	"github.com/AliMousaviSoft/subjackal/internal/resolve"
)

type Config struct {
	Threads    int
	Resolver   *resolve.Resolver
	Prober     *probe.HTTPProber
	Analyzer   *analyze.Analyzer
	Enumerator enum.Enumerator
}

type Pipeline struct {
	cfg Config
}

func New(cfg Config) *Pipeline {
	return &Pipeline{cfg: cfg}
}

func (p *Pipeline) Run(ctx context.Context, domain string) <-chan *model.Subdomain {
	results := make(chan *model.Subdomain, 100)
	go func() {
		defer close(results)

		subdomains, err := p.cfg.Enumerator.Enumerate(ctx, domain)
		if err != nil {
			return
		}

		// skip wildcard detection in file mode (no root domain)
		var isWildcard bool
		var wildcardIP string
		if domain != "" {
			isWildcard, wildcardIP = p.cfg.Resolver.DetectWildcard(ctx, domain)
		}

		var wg sync.WaitGroup
		sem := make(chan struct{}, p.cfg.Threads)

		for sub := range subdomains {
			sub := sub
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				result := p.processSubdomain(ctx, sub, domain, isWildcard, wildcardIP)
				if result != nil {
					select {
					case <-ctx.Done():
					case results <- result:
					}
				}
			}()
		}
		wg.Wait()
	}()
	return results
}

func (p *Pipeline) processSubdomain(ctx context.Context, subdomain, root string, isWildcard bool, wildcardIP string) *model.Subdomain {
	sub := &model.Subdomain{Domain: subdomain, Root: root}

	chain, final, err := p.cfg.Resolver.ResolveCNAMEChain(ctx, subdomain)
	if err == nil && len(chain) > 0 {
		sub.RecordType = model.RecordCNAME
		sub.CNAMEChain = chain
		sub.CNAMETarget = final
	}

	if sub.RecordType == "" {
		ips, err := p.cfg.Resolver.LookupA(ctx, subdomain)
		if err == nil && len(ips) > 0 {
			sub.RecordType = model.RecordA
			sub.IPs = ips
			if isWildcard && wildcardIP != "" {
				for _, ip := range ips {
					if ip == wildcardIP {
						sub.IsWildcard = true
						sub.Status = model.StatusAlive
						sub.Note = "Wildcard DNS — skipped"
						return sub
					}
				}
			}
		}
	}

	if sub.RecordType == "" {
		ns, err := p.cfg.Resolver.LookupNS(ctx, subdomain)
		if err == nil && len(ns) > 0 {
			sub.RecordType = model.RecordNS
			sub.NSRecords = ns
		}
	}

	if sub.RecordType == "" {
		nxdomain, err := p.cfg.Resolver.IsNXDOMAIN(ctx, subdomain)
		if err == nil && nxdomain {
			sub.RecordType = model.RecordNXDOMAIN
		}
	}

	p.cfg.Analyzer.Analyze(ctx, sub)

	if sub.Status == model.StatusSuspicious && p.cfg.Prober != nil {
		p.cfg.Prober.Probe(ctx, sub)
	}

	return sub
}
