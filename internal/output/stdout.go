package output

import (
	"fmt"
	"os"
	"strconv"

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

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func PrintProgress(total int, frame int) {
	spinner := spinnerFrames[frame%len(spinnerFrames)]
	fmt.Fprintf(os.Stderr, "\r%s%s Processing... (%d resolved)%s",
		colorCyan, spinner, total, colorReset,
	)
}

func ClearProgress() {
	fmt.Fprintf(os.Stderr, "\r\033[2K")
}

func PrintBanner(target string) {
	fmt.Printf("%s", colorCyan)
	fmt.Printf("                                                         \n")
	fmt.Printf("      -----.                                             \n")
	fmt.Printf("      \"   _}                                             \n")
	fmt.Printf("      \"@   >                                             \n")
	fmt.Printf("      |\\   7                                             \n")
	fmt.Printf("      / `-- _         ,-------,                          \n")
	fmt.Printf("   ~    >o<  \\---------o{___}-  ")

	if target != "" {
		fmt.Printf("%s%s%s%s", colorBold, colorRed, target, colorCyan)
	}
	fmt.Printf("\n")

	fmt.Printf("  /  |  \\  /  ________/8'                               \n")
	fmt.Printf("  |  |       /         \"                                 \n")
	fmt.Printf("  |  /      |                                            \n")
	fmt.Printf("%s\n", colorReset)

	fmt.Printf("%s", colorBold)
	fmt.Printf("  ░██████╗██╗   ██╗██████╗      ██╗ █████╗  ██████╗██╗  ██╗ █████╗ ██╗     \n")
	fmt.Printf("  ██╔════╝██║   ██║██╔══██╗     ██║██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██║     \n")
	fmt.Printf("  ╚█████╗ ██║   ██║██████╔╝     ██║███████║██║     █████╔╝ ███████║██║     \n")
	fmt.Printf("   ╚═══██╗██║   ██║██╔══██╗██   ██║██╔══██║██║     ██╔═██╗ ██╔══██║██║     \n")
	fmt.Printf("  ██████╔╝╚██████╔╝██████╔╝╚█████╔╝██║  ██║╚██████╗██║  ██╗██║  ██║███████╗\n")
	fmt.Printf("  ╚═════╝  ╚═════╝ ╚═════╝  ╚════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝\n")
	fmt.Printf("%s", colorReset)

	fmt.Printf("%s                subdomain takeover hunter%s\n\n", colorCyan, colorReset)
}

func PrintResult(sub *model.Subdomain, silent bool) {
	switch sub.Status {
	case model.StatusVulnerable:
		fmt.Printf("%s%s[VULNERABLE]%s %s\n", colorBold, colorRed, colorReset, sub.Domain)
		fmt.Printf("             service    : %s\n", sub.ServiceProvider)
		fmt.Printf("             confidence : %s (score: %s)\n",
			string(sub.Confidence), strconv.Itoa(sub.Score.Total()))
		fmt.Printf("             note       : %s\n", sub.Note)

	case model.StatusSuspicious:
		service := sub.ServiceProvider
		if service == "" {
			service = "unknown"
		}
		fmt.Printf("%s[SUSPICIOUS]%s %s — CNAME → %s (%s confidence, score: %s)\n",
			colorYellow, colorReset,
			sub.Domain, service,
			string(sub.Confidence),
			strconv.Itoa(sub.Score.Total()),
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