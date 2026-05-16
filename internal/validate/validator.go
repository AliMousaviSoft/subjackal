package validate

import (
	"context"
	"fmt"
	"strings"

	"github.com/AliMousaviSoft/subjackal/internal/model"
	"github.com/AliMousaviSoft/subjackal/internal/resolve"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorGray   = "\033[90m"
)

type ValidationReport struct {
	Domain       string
	Provider     string
	CNAMEChain   []string
	FinalTarget  string
	FinalIPs     []string
	Wayback      WaybackResult
	CTLog        CTLogResult
	Verification VerificationResult
	Provider_    ProviderResult
	Verdict      string
	VerdictScore int
	ScoreBreakdown []string
}

func Validate(ctx context.Context, r *resolve.Resolver, sub *model.Subdomain) *ValidationReport {
	report := &ValidationReport{
		Domain:      sub.Domain,
		Provider:    sub.ServiceProvider,
		CNAMEChain:  sub.CNAMEChain,
		FinalTarget: sub.CNAMETarget,
		FinalIPs:    sub.IPs, // already resolved in pipeline
	}

	// resolve final target IPs
	if sub.CNAMETarget != "" {
		ips, _ := r.LookupA(ctx, sub.CNAMETarget)
		report.FinalIPs = ips
	}

	// run all checks
	report.Wayback = CheckWayback(ctx, sub.Domain)
	report.CTLog = CheckCTLog(ctx, sub.Domain)
	report.Verification = CheckVerification(ctx, r, sub.Domain, sub.ServiceProvider)
	report.Provider_ = CheckProvider(ctx, sub.Domain, sub.ServiceProvider)

	// scoring with breakdown
	score := 0

	if report.Wayback.Found {
		score += 20
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			fmt.Sprintf("+20 wayback: was indexed (last seen %s, %d snapshots)",
				report.Wayback.LastSeen, report.Wayback.Total))
	} else {
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			"+0  wayback: no archive history found")
	}

	if report.CTLog.Found {
		score += 20
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			fmt.Sprintf("+20 ct log: cert issued %s via %s",
				report.CTLog.IssuedDate, report.CTLog.Issuer))
	} else {
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			"+0  ct log: no certificate history")
	}

	if !report.Verification.Locked {
		score += 30
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			"+30 verification: no ownership lock in DNS")
	} else {
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			fmt.Sprintf("+0  verification: LOCKED — %s", report.Verification.Reason))
	}

	// replace the provider HTTP scoring block with this:
	if report.Provider_.Reclaimable {
		score += 30
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			fmt.Sprintf("+30 provider http: reclaimable — %s (HTTP %d)",
				report.Provider_.Reason, report.Provider_.HTTPStatus))
	} else if report.Provider_.HTTPStatus == 0 && len(report.FinalIPs) == 0 {
		// HTTP unreachable because domain is NXDOMAIN — this is expected for dangling
		// don't penalize, treat as neutral
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			"+0  provider http: unreachable (expected — final target is NXDOMAIN)")
	} else {
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			fmt.Sprintf("+0  provider http: not reclaimable — %s (HTTP %d)",
				report.Provider_.Reason, report.Provider_.HTTPStatus))
	}

	// penalty: if final target IPs exist, chain is not dangling
	if len(report.FinalIPs) == 0 && report.FinalTarget != "" {
		score += 20
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			"+20 final target: NXDOMAIN confirmed — chain is genuinely dangling")
	} else if len(report.FinalIPs) > 0 {
		score -= 50
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			fmt.Sprintf("-50 final target resolves to IP: %s (not dangling)",
				strings.Join(report.FinalIPs, ", ")))
	}

	report.VerdictScore = score

	switch {
	case score >= 80:
		report.Verdict = "HIGH — worth manual attempt"
	case score >= 50:
		report.Verdict = "MEDIUM — investigate further"
	case score >= 30:
		report.Verdict = "LOW — likely false positive"
	default:
		report.Verdict = "NOISE — skip"
	}

	return report
}

func PrintReport(r *ValidationReport) {
	fmt.Printf("\n%s[VALIDATE]%s %s%s%s\n",
		colorBold, colorReset,
		colorCyan, r.Domain, colorReset,
	)

	// CNAME chain
	if len(r.CNAMEChain) > 0 {
		fmt.Printf("  %s│%s\n", colorGray, colorReset)
		fmt.Printf("  %s├── CNAME chain%s\n", colorGray, colorReset)
		fmt.Printf("  %s│   %s%s%s\n", colorGray, colorCyan,
			strings.Join(r.CNAMEChain, "\n  │   → "), colorReset)

		if r.FinalTarget != "" {
			if len(r.FinalIPs) > 0 {
				fmt.Printf("  %s│   → final: %s%s%s (%s%s✓ resolves to %s%s)\n",
					colorGray,
					colorGreen, r.FinalTarget, colorReset,
					colorGreen, "", strings.Join(r.FinalIPs, ", "), colorReset)
			} else {
				fmt.Printf("  %s│   → final: %s%s%s (%sNXDOMAIN — dangling%s)\n",
					colorGray,
					colorRed, r.FinalTarget, colorReset,
					colorRed, colorReset)
			}
		}
		fmt.Printf("  %s│%s\n", colorGray, colorReset)
	}

	// Wayback
	if r.Wayback.Found {
		fmt.Printf("  %s├── Wayback check   %s: %slast seen %s (%d snapshots)%s\n",
			colorGreen, colorReset, colorGreen, r.Wayback.LastSeen, r.Wayback.Total, colorReset)
	} else {
		fmt.Printf("  %s├── Wayback check   %s: %sno archive entries%s\n",
			colorYellow, colorReset, colorYellow, colorReset)
	}

	// CT Log
	if r.CTLog.Found {
		fmt.Printf("  %s├── CT log check    %s: %scert issued %s (%s)%s\n",
			colorGreen, colorReset, colorGreen, r.CTLog.IssuedDate, r.CTLog.Issuer, colorReset)
	} else {
		fmt.Printf("  %s├── CT log check    %s: %sno cert history%s\n",
			colorYellow, colorReset, colorYellow, colorReset)
	}

	// Verification DNS
	if r.Verification.Locked {
		fmt.Printf("  %s├── Verification DNS%s: %sLOCKED — %s%s\n",
			colorRed, colorReset, colorRed, r.Verification.Reason, colorReset)
	} else {
		fmt.Printf("  %s├── Verification DNS%s: %sno ownership lock found%s\n",
			colorGreen, colorReset, colorGreen, colorReset)
	}

	// Provider HTTP
	if r.Provider_.Reclaimable {
		fmt.Printf("  %s├── Provider HTTP   %s: %sRECLAIMABLE — %s (HTTP %d)%s\n",
			colorGreen, colorReset, colorGreen, r.Provider_.Reason, r.Provider_.HTTPStatus, colorReset)
	} else {
		fmt.Printf("  %s├── Provider HTTP   %s: %s%s (HTTP %d)%s\n",
			colorRed, colorReset, colorRed, r.Provider_.Reason, r.Provider_.HTTPStatus, colorReset)
	}

	// Score breakdown
	fmt.Printf("  %s│%s\n", colorGray, colorReset)
	fmt.Printf("  %s├── Score breakdown%s\n", colorGray, colorReset)
	for i, line := range r.ScoreBreakdown {
		prefix := "│   ├──"
		if i == len(r.ScoreBreakdown)-1 {
			prefix = "│   └──"
		}
		color := colorGreen
		if strings.HasPrefix(line, "+0") || strings.HasPrefix(line, "-") {
			color = colorYellow
			if strings.HasPrefix(line, "-") {
				color = colorRed
			}
		}
		fmt.Printf("  %s%s %s%s%s\n", colorGray, prefix, color, line, colorReset)
	}
	fmt.Printf("  %s│%s\n", colorGray, colorReset)

	// Verdict
	verdictColor := colorRed
	switch {
	case r.VerdictScore >= 80:
		verdictColor = colorGreen
	case r.VerdictScore >= 50:
		verdictColor = colorYellow
	}

	fmt.Printf("  %s└── Verdict         %s: %s%s%s (score: %d/100)%s\n\n",
		colorBold, colorReset,
		colorBold+verdictColor, r.Verdict, colorReset,
		r.VerdictScore, colorReset,
	)
}