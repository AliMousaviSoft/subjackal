package analyze

import (
	"context"
	"strings"

	"github.com/AliMousaviSoft/subjackal/internal/model"
	"github.com/AliMousaviSoft/subjackal/internal/resolve"
)

type Analyzer struct {
	resolver *resolve.Resolver
}

func New(r *resolve.Resolver) *Analyzer {
	return &Analyzer{resolver: r}
}

func (a *Analyzer) Analyze(ctx context.Context, sub *model.Subdomain) {
	switch sub.RecordType {
	case model.RecordNXDOMAIN:
		sub.Status = model.StatusNXDOMAIN
		sub.Note = "NXDOMAIN — no DNS record exists"
	case model.RecordCNAME:
		a.analyzeCNAME(ctx, sub)
	case model.RecordNS:
		a.analyzeNS(ctx, sub)
	default:
		sub.Status = model.StatusAlive
	}
}

func (a *Analyzer) analyzeCNAME(ctx context.Context, sub *model.Subdomain) {
	if sub.CNAMETarget == "" {
		sub.Status = model.StatusAlive
		return
	}
	fp := MatchCNAME(sub.CNAMETarget)
	if fp == nil {
		sub.Status = model.StatusAlive
		sub.Note = "CNAME to unknown service"
		return
	}
	if !fp.TakeoverPossible {
		sub.Status = model.StatusAlive
		sub.ServiceProvider = fp.Name
		sub.Note = "CNAME to " + fp.Name + " — takeover not possible"
		return
	}
	nxdomain, err := a.resolver.IsNXDOMAIN(ctx, sub.CNAMETarget)
	if err != nil {
		sub.Note = "CNAME resolution error: " + err.Error()
		return
	}
	sub.ServiceProvider = fp.Name
	sub.Fingerprint = fp.HTTPFingerprint
	if nxdomain {
		sub.TakeoverPossible = true
		sub.Status = model.StatusSuspicious
		sub.Confidence = model.ConfidenceMedium
		sub.Note = "CNAME → " + fp.Name + " (NXDOMAIN) — HTTP probe needed"
	} else {
		sub.Status = model.StatusAlive
		sub.Confidence = model.ConfidenceLow
		sub.Note = "CNAME → " + fp.Name + " — target resolves, HTTP probe required"
	}
}

func (a *Analyzer) analyzeNS(ctx context.Context, sub *model.Subdomain) {
	for _, ns := range sub.NSRecords {
		ns = strings.TrimSuffix(ns, ".")
		nsDomain := extractRootDomain(ns)
		if nsDomain == "" {
			continue
		}
		nxdomain, err := a.resolver.IsNXDOMAIN(ctx, nsDomain)
		if err != nil {
			continue
		}
		if nxdomain {
			sub.TakeoverPossible = true
			sub.Status = model.StatusVulnerable
			sub.Confidence = model.ConfidenceHigh
			sub.Note = "NS delegation to unregistered domain: " + nsDomain + " — FULL ZONE TAKEOVER POSSIBLE"
			return
		}
	}
	sub.Status = model.StatusAlive
}

func extractRootDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
