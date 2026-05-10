package output

import (
	"fmt"

	"github.com/AliMousaviSoft/subjackal/internal/model"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func PrintResult(sub *model.Subdomain, silent bool) {
	switch sub.Status {
	case model.StatusVulnerable:
		fmt.Printf("%s%s[VULNERABLE]%s %s\n", colorBold, colorRed, colorReset, sub.Domain)
		fmt.Printf("             service    : %s\n", sub.ServiceProvider)
		fmt.Printf("             confidence : %s\n", sub.Confidence)
		fmt.Printf("             note       : %s\n", sub.Note)

	case model.StatusSuspicious:
		service := sub.ServiceProvider
		if service == "" {
			service = "unknown"
		}
		fmt.Printf("%s[SUSPICIOUS]%s %s — %s (%s confidence)\n",
			colorYellow, colorReset,
			sub.Domain, service, sub.Confidence,
		)

	case model.StatusNXDOMAIN:
		if !silent {
			fmt.Printf("%s[NXDOMAIN]%s   %s\n", colorCyan, colorReset, sub.Domain)
		}

	case model.StatusAlive:
		if !silent {
			fmt.Printf("%s[ALIVE]%s      %s\n", colorGreen, colorReset, sub.Domain)
		}
	}
}

func PrintBanner() {
	fmt.Printf("%s subjackal — subdomain takeover hunter%s\n\n", colorBold, colorReset)
}