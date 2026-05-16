package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	Domain         string          `json:"domain"`
	Provider       string          `json:"provider"`
	CNAMEChain     []string        `json:"cname_chain"`
	FinalTarget    string          `json:"final_target"`
	FinalIPs       []string        `json:"final_ips"`
	Wayback        WaybackResult   `json:"wayback"`
	CTLog          CTLogResult     `json:"ct_log"`
	Verification   VerificationResult `json:"verification"`
	ProviderCheck  ProviderResult  `json:"provider_check"`
	Verdict        string          `json:"verdict"`
	VerdictScore   int             `json:"verdict_score"`
	ScoreBreakdown []string        `json:"score_breakdown"`
}

func Validate(ctx context.Context, r *resolve.Resolver, sub *model.Subdomain) *ValidationReport {
	report := &ValidationReport{
		Domain:      sub.Domain,
		Provider:    sub.ServiceProvider,
		CNAMEChain:  sub.CNAMEChain,
		FinalTarget: sub.CNAMETarget,
		FinalIPs:    sub.IPs,
	}

	report.Wayback = CheckWayback(ctx, sub.Domain)
	report.CTLog = CheckCTLog(ctx, sub.Domain)
	report.Verification = CheckVerification(ctx, r, sub.Domain, sub.ServiceProvider)
	report.ProviderCheck = CheckProvider(ctx, sub.Domain, sub.ServiceProvider)

	score := 0
	signals := 0 // count positive signals

	if report.Wayback.Found {
		score += 20
		signals++
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			fmt.Sprintf("+20 wayback: was indexed (last seen %s, %d snapshots)",
				report.Wayback.LastSeen, report.Wayback.Total))
	} else {
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			"+0  wayback: no archive history found")
	}

	if report.CTLog.Found {
		score += 20
		signals++
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			fmt.Sprintf("+20 ct log: cert issued %s via %s (total: %d certs)",
				report.CTLog.IssuedDate, report.CTLog.Issuer, report.CTLog.Total))
	} else {
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			"+0  ct log: no certificate history")
	}

	if !report.Verification.Locked {
		score += 30
		signals++
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			"+30 verification: no provider ownership lock in DNS")
	} else {
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			fmt.Sprintf("+0  verification: LOCKED — %s", report.Verification.Reason))
	}

	if report.ProviderCheck.Reclaimable {
		score += 30
		signals++
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			fmt.Sprintf("+30 provider http: reclaimable — %s (HTTP %d)",
				report.ProviderCheck.Reason, report.ProviderCheck.HTTPStatus))
	} else if report.ProviderCheck.HTTPStatus == 0 && len(report.FinalIPs) == 0 {
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			"+0  provider http: unreachable (expected — final target is NXDOMAIN)")
	} else {
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			fmt.Sprintf("+0  provider http: not reclaimable — %s (HTTP %d)",
				report.ProviderCheck.Reason, report.ProviderCheck.HTTPStatus))
	}

	if len(report.FinalIPs) == 0 && report.FinalTarget != "" {
		score += 20
		signals++
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			"+20 final target: NXDOMAIN confirmed — chain is genuinely dangling")
	} else if len(report.FinalIPs) > 0 {
		score -= 50
		report.ScoreBreakdown = append(report.ScoreBreakdown,
			fmt.Sprintf("-50 final target resolves to IP: %s (not dangling)",
				strings.Join(report.FinalIPs, ", ")))
	}

	if score < 0 {
		score = 0
	}

	report.VerdictScore = score

	// require at least 2 positive signals for MEDIUM
	// prevents single-signal noise from reaching actionable verdict
	switch {
	case score >= 80 && signals >= 3:
		report.Verdict = "HIGH — worth manual attempt"
	case score >= 50 && signals >= 2:
		report.Verdict = "MEDIUM — investigate further"
	case score >= 30:
		report.Verdict = "LOW — likely false positive"
	default:
		report.Verdict = "NOISE — skip"
	}

	return report
}

// WriteJSON appends a validation report to a JSON file
func (r *ValidationReport) WriteJSON(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func PrintReport(r *ValidationReport) {
	fmt.Printf("\n%s[VALIDATE]%s %s%s%s\n",
		colorBold, colorReset,
		colorCyan, r.Domain, colorReset,
	)

	if len(r.CNAMEChain) > 0 {
		fmt.Printf("  %s│%s\n", colorGray, colorReset)
		fmt.Printf("  %s├── CNAME chain%s\n", colorGray, colorReset)
		for _, hop := range r.CNAMEChain {
			fmt.Printf("  %s│   → %s%s%s\n", colorGray, colorCyan, hop, colorReset)
		}
		if r.FinalTarget != "" {
			if len(r.FinalIPs) > 0 {
				fmt.Printf("  %s│   → final: %s%s%s (%s✓ %s%s)\n",
					colorGray, colorGreen, r.FinalTarget, colorReset,
					colorGreen, strings.Join(r.FinalIPs, ", "), colorReset)
			} else {
				fmt.Printf("  %s│   → final: %s%s%s (%sNXDOMAIN — dangling%s)\n",
					colorGray, colorRed, r.FinalTarget, colorReset,
					colorRed, colorReset)
			}
		}
		fmt.Printf("  %s│%s\n", colorGray, colorReset)
	}

	if r.Wayback.Found {
		fmt.Printf("  %s├── Wayback check   %s: %slast seen %s (%d snapshots)%s\n",
			colorGreen, colorReset, colorGreen, r.Wayback.LastSeen, r.Wayback.Total, colorReset)
	} else {
		fmt.Printf("  %s├── Wayback check   %s: %sno archive entries%s\n",
			colorYellow, colorReset, colorYellow, colorReset)
	}

	if r.CTLog.Found {
		fmt.Printf("  %s├── CT log check    %s: %scert issued %s via %s (total: %d)%s\n",
			colorGreen, colorReset, colorGreen,
			r.CTLog.IssuedDate, r.CTLog.Issuer, r.CTLog.Total, colorReset)
	} else {
		fmt.Printf("  %s├── CT log check    %s: %sno cert history%s\n",
			colorYellow, colorReset, colorYellow, colorReset)
	}

	if r.Verification.Locked {
		fmt.Printf("  %s├── Verification DNS%s: %sLOCKED — %s%s\n",
			colorRed, colorReset, colorRed, r.Verification.Reason, colorReset)
	} else {
		fmt.Printf("  %s├── Verification DNS%s: %sno provider ownership lock%s\n",
			colorGreen, colorReset, colorGreen, colorReset)
	}

	if r.ProviderCheck.Reclaimable {
		fmt.Printf("  %s├── Provider HTTP   %s: %sRECLAIMABLE — %s (HTTP %d)%s\n",
			colorGreen, colorReset, colorGreen,
			r.ProviderCheck.Reason, r.ProviderCheck.HTTPStatus, colorReset)
	} else {
		fmt.Printf("  %s├── Provider HTTP   %s: %s%s (HTTP %d)%s\n",
			colorRed, colorReset, colorRed,
			r.ProviderCheck.Reason, r.ProviderCheck.HTTPStatus, colorReset)
	}

	fmt.Printf("  %s│%s\n", colorGray, colorReset)
	fmt.Printf("  %s├── Score breakdown%s\n", colorGray, colorReset)
	for i, line := range r.ScoreBreakdown {
		prefix := "│   ├──"
		if i == len(r.ScoreBreakdown)-1 {
			prefix = "│   └──"
		}
		color := colorGreen
		if strings.HasPrefix(line, "+0") {
			color = colorYellow
		} else if strings.HasPrefix(line, "-") {
			color = colorRed
		}
		fmt.Printf("  %s%s %s%s%s\n", colorGray, prefix, color, line, colorReset)
	}
	fmt.Printf("  %s│%s\n", colorGray, colorReset)

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