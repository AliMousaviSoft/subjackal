package validate

import (
	"context"
	"strings"

	"github.com/AliMousaviSoft/subjackal/internal/resolve"
)

type VerificationResult struct {
	Locked  bool
	Records []string
	Reason  string
}

// provider-specific TXT record prefixes that indicate ownership lock
var verificationPrefixes = map[string][]string{
	"Microsoft Azure": {
		"asuid.",
		"_dnsauth.",
	},
	"GitHub Pages": {
		"_github-pages-challenge-",
	},
	"Cloudflare": {
		"_cf-custom-hostname-verification.",
	},
	"Shopify": {
		"shopify-verification.",
	},
	"Heroku": {
		"_heroku.",
	},
	"Vercel": {
		"_vercel.",
	},
	"Netlify": {
		"_netlify.",
	},
	"AWS/S3": {
		"_amazonses.",
	},
	"default": {
		"_acme-challenge.",
		"_domainkey.",
		"_verification.",
		"_ownership.",
	},
}

func CheckVerification(ctx context.Context, r *resolve.Resolver, domain, provider string) VerificationResult {
	prefixes := verificationPrefixes["default"]
	if p, ok := verificationPrefixes[provider]; ok {
		prefixes = append(prefixes, p...)
	}

	for _, prefix := range prefixes {
		checkDomain := prefix + domain
		// strip trailing dot if any
		checkDomain = strings.TrimSuffix(checkDomain, ".")

		ips, _ := r.LookupA(ctx, checkDomain)
		ns, _ := r.LookupNS(ctx, checkDomain)

		// also check TXT via generic A lookup — if it resolves, record exists
		nxdomain, _ := r.IsNXDOMAIN(ctx, checkDomain)

		if !nxdomain || len(ips) > 0 || len(ns) > 0 {
			return VerificationResult{
				Locked:  true,
				Records: []string{checkDomain},
				Reason:  "ownership verification record found: " + checkDomain,
			}
		}
	}

	return VerificationResult{Locked: false}
}