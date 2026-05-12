package analyze

import (
	"context"
	"strconv"
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
		a.analyzeNXDOMAIN(ctx, sub)
	case model.RecordCNAME:
		a.analyzeCNAME(ctx, sub)
	case model.RecordNS:
		a.analyzeNS(ctx, sub)
	default:
		sub.Status = model.StatusAlive
	}
}

func (a *Analyzer) analyzeNXDOMAIN(ctx context.Context, sub *model.Subdomain) {
	// even on NXDOMAIN, check for dangling CNAME
	chain, final, err := a.resolver.ResolveCNAMEChain(ctx, sub.Domain)
	if err == nil && len(chain) > 0 {
		sub.RecordType = model.RecordCNAME
		sub.CNAMEChain = chain
		sub.CNAMETarget = final
		a.analyzeCNAME(ctx, sub)
		return
	}

	sub.Status = model.StatusNXDOMAIN
	sub.Note = "NXDOMAIN — no DNS record exists"
}

func (a *Analyzer) analyzeCNAME(ctx context.Context, sub *model.Subdomain) {
	if sub.CNAMETarget == "" {
		sub.Status = model.StatusAlive
		return
	}

	fp := MatchCNAME(sub.CNAMETarget)
	if fp == nil {
		sub.Status = model.StatusAlive
		sub.Note = "CNAME to unknown service — " + sub.CNAMETarget
		return
	}

	sub.ServiceProvider = fp.Name
	sub.Fingerprint = fp.HTTPFingerprint
	sub.Score.CNAMEMatch = 70

	if !fp.TakeoverPossible {
		sub.Status = model.StatusAlive
		sub.Note = "CNAME to " + fp.Name + " [" + fp.Status + "] — takeover not possible"
		return
	}

	// for nxdomain_only services (Azure, Elastic Beanstalk etc.)
	// confirmation comes from NXDOMAIN, not HTTP body
	nxdomain, err := a.resolver.IsNXDOMAIN(ctx, sub.CNAMETarget)
	if err == nil && nxdomain {
		sub.Score.NXDOMAINBack = 20
		if fp.NXDOMAINOnly {
			// NXDOMAIN is the confirmation for these services
			sub.Score.HTTPMatch = 100
			sub.TakeoverPossible = true
			sub.Status = model.StatusVulnerable
			sub.Confidence = model.ConfidenceHigh
			sub.Note = "CONFIRMED — " + fp.Name + " [" + fp.Status + "] CNAME target NXDOMAIN — score: " +
				strconv.Itoa(sub.Score.Total())
			return
		}
	}

	total := sub.Score.Total()
	sub.Confidence = sub.Score.Level()

	if total >= 50 {
		sub.TakeoverPossible = true
		sub.Status = model.StatusSuspicious
		sub.Note = buildNote(sub, nxdomain, fp.Status)
	} else {
		sub.Status = model.StatusAlive
		sub.Note = "CNAME → " + fp.Name + " [" + fp.Status + "] — score too low (" +
			strconv.Itoa(total) + "/50)"
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
			sub.Score.NSUnregistered = 150
			sub.TakeoverPossible = true
			sub.Status = model.StatusVulnerable
			sub.Confidence = model.ConfidenceHigh
			sub.Note = "NS delegation to unregistered domain: " + nsDomain + " — FULL ZONE TAKEOVER POSSIBLE"
			return
		}
	}
	sub.Status = model.StatusAlive
}

func buildNote(sub *model.Subdomain, nxdomain bool, fpStatus string) string {
	note := "CNAME → " + sub.ServiceProvider + " [" + fpStatus + "]"
	if nxdomain {
		note += " (backend NXDOMAIN)"
	}
	note += " — score: " + strconv.Itoa(sub.Score.Total())
	note += " — HTTP probe required to confirm"
	return note
}

func extractRootDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}