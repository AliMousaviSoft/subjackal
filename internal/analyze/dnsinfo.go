package analyze

import (
	"context"
	"fmt"
	"strings"

	"github.com/AliMousaviSoft/subjackal/internal/model"
	"github.com/AliMousaviSoft/subjackal/internal/resolve"
)

type DNSInfo struct {
	CNAME              []string
	A                  []string
	AAAA               []string
	NS                 []string
	MX                 []string
	IsThirdParty       bool
	ThirdPartyProvider string
}

func InspectDNS(ctx context.Context, r *resolve.Resolver, sub *model.Subdomain) *DNSInfo {
	info := &DNSInfo{}

	if len(sub.CNAMEChain) > 0 {
		info.CNAME = sub.CNAMEChain
	}

	ips, _ := r.LookupA(ctx, sub.Domain)
	info.A = ips

	aaaa, _ := r.LookupAAAA(ctx, sub.Domain)
	info.AAAA = aaaa

	ns, _ := r.LookupNS(ctx, sub.Domain)
	info.NS = ns

	mx, _ := r.LookupMX(ctx, sub.Domain)
	info.MX = mx

	if sub.CNAMETarget != "" {
		fp := MatchCNAME(sub.CNAMETarget)
		if fp != nil {
			info.IsThirdParty = true
			info.ThirdPartyProvider = fp.Name
		} else {
			info.IsThirdParty = isDifferentDomain(sub.Domain, sub.CNAMETarget)
		}
	}

	return info
}

func PrintDNSInfo(domain string, info *DNSInfo) {
	fmt.Printf("  \033[1m[DNS Info] %s\033[0m\n", domain)

	if len(info.CNAME) > 0 {
		fmt.Printf("  CNAME chain : %s\n", strings.Join(info.CNAME, " → "))
		if info.IsThirdParty {
			provider := info.ThirdPartyProvider
			if provider == "" {
				provider = "unknown third-party"
			}
			fmt.Printf("  3rd party   : \033[33mYES (%s)\033[0m\n", provider)
		} else {
			fmt.Printf("  3rd party   : NO\n")
		}
	}

	if len(info.A) > 0 {
		fmt.Printf("  A           : %s\n", strings.Join(info.A, ", "))
	}
	if len(info.AAAA) > 0 {
		fmt.Printf("  AAAA        : %s\n", strings.Join(info.AAAA, ", "))
	}
	if len(info.NS) > 0 {
		fmt.Printf("  NS          : %s\n", strings.Join(info.NS, ", "))
	}
	if len(info.MX) > 0 {
		fmt.Printf("  MX          : %s\n", strings.Join(info.MX, ", "))
	}
	if len(info.A) == 0 && len(info.AAAA) == 0 && len(info.CNAME) == 0 && len(info.NS) == 0 {
		fmt.Printf("  \033[31mno records found\033[0m\n")
	}
	fmt.Println()
}

func isDifferentDomain(origin, cname string) bool {
	originRoot := extractRootDomain(origin)
	cnameRoot := extractRootDomain(strings.TrimSuffix(cname, "."))
	return originRoot != cnameRoot && cnameRoot != ""
}