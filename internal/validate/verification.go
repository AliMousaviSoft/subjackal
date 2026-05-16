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

// providerVerificationRecords maps service → DNS prefixes that indicate
// the provider has an ownership/verification lock on that subdomain.
// These are provider-specific — NOT generic ACME challenge records.
// _acme-challenge is excluded: it's used for cert issuance, not ownership lock.
var providerVerificationRecords = map[string][]string{
	"Microsoft Azure": {
		"asuid.",              // Azure App Service custom domain verification
		"_dnsauth.",           // Azure Front Door / CDN verification
	},
	"GitHub Pages": {
		"_github-pages-challenge-",
	},
	"Cloudflare": {
		"_cf-custom-hostname-verification.",
	},
	"Shopify": {
		"shopify.",
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
	"AWS/Elastic Beanstalk": {
		"_awselb.",
	},
}

// genericOwnershipRecords — truly global ownership signals
// (not ACME, not provider-specific cert issuance)
var genericOwnershipRecords = []string{
	"_ownership.",
	"_domainconnect.",
	"_domainkey.",   // DKIM — signals active mail config, not takeover lock
}

func CheckVerification(ctx context.Context, r *resolve.Resolver, domain, provider string) VerificationResult {
	var prefixes []string

	// provider-specific first
	if p, ok := providerVerificationRecords[provider]; ok {
		prefixes = append(prefixes, p...)
	}

	// generic ownership signals
	prefixes = append(prefixes, genericOwnershipRecords...)

	for _, prefix := range prefixes {
		checkDomain := prefix + domain
		checkDomain = strings.TrimSuffix(checkDomain, ".")

		nxdomain, err := r.IsNXDOMAIN(ctx, checkDomain)
		if err != nil {
			continue
		}

		if !nxdomain {
			return VerificationResult{
				Locked:  true,
				Records: []string{checkDomain},
				Reason:  "ownership verification record found: " + checkDomain,
			}
		}
	}

	return VerificationResult{Locked: false}
}