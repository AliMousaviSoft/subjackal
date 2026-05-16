package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	
	validatepkg "github.com/AliMousaviSoft/subjackal/internal/validate"
	"github.com/AliMousaviSoft/subjackal/internal/analyze"
	"github.com/AliMousaviSoft/subjackal/internal/enum"
	"github.com/AliMousaviSoft/subjackal/internal/model"
	"github.com/AliMousaviSoft/subjackal/internal/output"
	"github.com/AliMousaviSoft/subjackal/internal/pipeline"
	"github.com/AliMousaviSoft/subjackal/internal/probe"
	"github.com/AliMousaviSoft/subjackal/internal/resolve"
	"github.com/spf13/cobra"
)

var (
	update      bool
	target      string
	targets     string
	subs        string
	threads     int
	timeoutMs   int
	httpTimeout int
	retries     int
	jsonOutput  bool
	outputFile  string
	resolvers   []string
	silent      bool
	debug       bool
	inspect     bool
	noHTTP      bool
	cnameOnly   bool
	noWildcard  bool
	onlyStatus  string
	exclude     []string
	include     []string
	matchSvc    []string
	fpFile      string
	verify      bool
	validate bool
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "subjackal",
	Short: "Subdomain takeover hunter",
	Run:   run,
}

func run(cmd *cobra.Command, args []string) {
	if update {
		doUpdate()
		return
	}

	// stdin support: cat subs.txt | subjackal
	stdinMode := false
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		stdinMode = true
	}

	domains := collectDomains()
	if len(domains) == 0 && subs == "" && !stdinMode {
		fmt.Fprintln(os.Stderr, "Error: provide --target, --targets, --subs, or pipe via stdin")
		cmd.Help()
		os.Exit(1)
	}

	if !silent {
		bannerTarget := target
		if subs != "" {
			bannerTarget = subs
		} else if targets != "" {
			bannerTarget = targets
		}
		output.PrintBanner(bannerTarget)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// enumerator selection
	var enumerator enum.Enumerator
	if stdinMode {
		enumerator = enum.NewReaderEnum(os.Stdin)
	} else if subs != "" {
		enumerator = enum.NewFileEnum(subs)
	} else {
		crtsh := enum.NewCrtSh()
		crtsh.Debug = debug
		enumerator = crtsh
	}

	if debug {
		domainLabel := "from file"
		if len(domains) > 0 {
			domainLabel = domains[0]
		}
		fmt.Printf("[debug] testing enumeration for: %s\n", domainLabel)
		subsCh, err := enumerator.Enumerate(ctx, domainLabel)
		if err != nil {
			fmt.Printf("[debug] enumerate error: %v\n", err)
			return
		}
		count := 0
		for s := range subsCh {
			fmt.Println("[debug] subdomain:", s)
			count++
		}
		fmt.Printf("[debug] total: %d subdomains\n", count)
		return
	}

	resolver := resolve.New(resolvers, time.Duration(timeoutMs)*time.Millisecond, retries)
	analyzer := analyze.New(resolver)

	var prober *probe.HTTPProber
	if !noHTTP {
		prober = probe.New(time.Duration(httpTimeout) * time.Millisecond)
	}

	// custom fingerprint file
	if fpFile != "" {
		if err := analyze.LoadFingerprintsFromFile(fpFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading fingerprints: %v\n", err)
			os.Exit(1)
		}
	}

	cfg := pipeline.Config{
		Threads:    threads,
		Resolver:   resolver,
		Analyzer:   analyzer,
		Prober:     prober,
		Enumerator: enumerator,
		NoWildcard: noWildcard,
		CNAMEOnly:  cnameOnly,
		Exclude:    exclude,
		Include:    include,
		Verify:     verify,
	}

	pipe := pipeline.New(cfg)

	var jw *output.JSONWriter
	if outputFile != "" {
		var err error
		jw, err = output.NewJSONWriter(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer jw.Close()
	}

	counts := map[model.Status]int{}
	total := 0
	frame := 0
	var dismissed []*model.Subdomain // collect dismissed separately
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()

	// build status filter
	filterStatus := parseStatusFilter(onlyStatus)
	// build service filter
	matchSet := make(map[string]bool)
	for _, m := range matchSvc {
		matchSet[strings.ToLower(m)] = true
	}

	shouldPrint := func(sub *model.Subdomain) bool {
		if sub.Status == model.StatusDismissed {
			return false // handled separately
		}
		if len(filterStatus) > 0 && !filterStatus[sub.Status] {
			return false
		}
		if len(matchSet) > 0 {
			if sub.Status == model.StatusSuspicious || sub.Status == model.StatusVulnerable {
				if !matchSet[strings.ToLower(sub.ServiceProvider)] {
					return false
				}
			}
		}
		return true
	}

	

	processResults := func(results <-chan *model.Subdomain) {
		for {
			select {
			case sub, ok := <-results:
				if !ok {
					return
				}

				total++
				counts[sub.Status]++

				if jw != nil {
					jw.Write(sub)
				}

				// collect dismissed separately
				if sub.Status == model.StatusDismissed {
					if verbose {
						dismissed = append(dismissed, sub)
					}
					continue
				}

				if !silent && shouldPrint(sub) {
					output.ClearProgress()
					output.PrintResult(sub, silent)

					if inspect && (sub.Status == model.StatusSuspicious || sub.Status == model.StatusVulnerable) {
						info := analyze.InspectDNS(ctx, resolver, sub)
						analyze.PrintDNSInfo(sub.Domain, info)
					}

					if validate && (sub.Status == model.StatusSuspicious || sub.Status == model.StatusVulnerable) {
						report := validatepkg.Validate(ctx, resolver, sub)
						validatepkg.PrintReport(report)
						// save validate report to file if -o given
						if outputFile != "" {
							report.WriteJSON(outputFile + ".validate.json")
						}
					}
				}

			case <-ticker.C:
				if !silent {
					output.PrintProgress(total, frame)
					frame++
				}

			case <-ctx.Done():
				return
			}
		}
	}

	if stdinMode || subs != "" {
		if !silent {
			label := "stdin"
			if subs != "" {
				label = subs
			}
			fmt.Printf("\n[*] Mode: file-based (%s)\n\n", label)
		}
		processResults(pipe.Run(ctx, ""))
	} else {
		for _, domain := range domains {
			if !silent {
				fmt.Printf("\n[*] Target: %s\n\n", domain)
			}
			processResults(pipe.Run(ctx, domain))
		}
	}

	if !silent {
		output.ClearProgress()
		fmt.Printf("\n%s--- Summary ---%s\n", "\033[1m", "\033[0m")
		fmt.Printf("  Vulnerable  : %d\n", counts[model.StatusVulnerable])
		fmt.Printf("  Suspicious  : %d\n", counts[model.StatusSuspicious])
		fmt.Printf("  NXDOMAIN    : %d\n", counts[model.StatusNXDOMAIN])
		fmt.Printf("  Alive       : %d\n", counts[model.StatusAlive])
		fmt.Printf("  Dismissed   : %d\n", counts[model.StatusDismissed])
		fmt.Printf("  Total       : %d\n", total)

		// print dismissed section at the end if --verbose
		if verbose && len(dismissed) > 0 {
			fmt.Printf("\n%s--- Dismissed Candidates ---%s\n", "\033[1m\033[33m", "\033[0m")
			fmt.Printf("%s(had CNAME to known service but chain resolved to live IP)%s\n\n",
				"\033[90m", "\033[0m")
			for _, sub := range dismissed {
				output.PrintDismissed(sub)
			}
		}
	}
}

func parseStatusFilter(only string) map[model.Status]bool {
	if only == "" {
		return nil
	}
	m := make(map[model.Status]bool)
	for _, s := range strings.Split(only, ",") {
		switch strings.TrimSpace(strings.ToLower(s)) {
		case "vulnerable":
			m[model.StatusVulnerable] = true
		case "suspicious":
			m[model.StatusSuspicious] = true
		case "nxdomain":
			m[model.StatusNXDOMAIN] = true
		case "alive":
			m[model.StatusAlive] = true
		case "dismissed":
    		m[model.StatusDismissed] = true
		}
	}
	return m
}

func doUpdate() {
	fmt.Println("Updating subjackal...")
	c := exec.Command("go", "install", "-v", "github.com/AliMousaviSoft/subjackal@latest")
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Updated successfully.")
}

func collectDomains() []string {
	var domains []string
	if target != "" {
		domains = append(domains, target)
	}
	if targets != "" {
		f, err := os.Open(targets)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening targets file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if line := scanner.Text(); line != "" {
				domains = append(domains, line)
			}
		}
	}
	seen := make(map[string]bool)
	unique := domains[:0]
	for _, d := range domains {
		if !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}
	return unique
}

func Execute() {
	rootCmd.Execute()
}

func init() {
	rootCmd.Flags().BoolVar(&update, "up", false, "Update to latest version")
	rootCmd.Flags().StringVar(&target, "target", "", "Single target domain")
	rootCmd.Flags().StringVar(&targets, "targets", "", "File with list of domains")
	rootCmd.Flags().StringVar(&subs, "subs", "", "File with pre-enumerated subdomains (skips crt.sh)")
	rootCmd.Flags().IntVar(&threads, "threads", 50, "Concurrency")
	rootCmd.Flags().IntVar(&timeoutMs, "timeout", 3000, "DNS timeout in ms")
	rootCmd.Flags().IntVar(&httpTimeout, "http-timeout", 5000, "HTTP timeout in ms")
	rootCmd.Flags().IntVar(&retries, "retries", 3, "DNS retry count")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "JSON output to stdout")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write JSON results to file")
	rootCmd.Flags().StringSliceVarP(&resolvers, "resolvers", "r", []string{}, "Custom resolvers")
	rootCmd.Flags().BoolVar(&silent, "silent", false, "Suppress terminal output")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "Debug mode: test enumeration only")
	rootCmd.Flags().BoolVar(&inspect, "inspect", false, "Show DNS detail for suspicious/vulnerable")
	rootCmd.Flags().BoolVar(&noHTTP, "no-http", false, "Skip HTTP probing (DNS-only mode)")
	rootCmd.Flags().BoolVar(&cnameOnly, "cname-only", false, "Only process subdomains with CNAME records")
	rootCmd.Flags().BoolVar(&noWildcard, "no-wildcard", false, "Disable wildcard detection")
	rootCmd.Flags().StringVar(&onlyStatus, "only", "", "Filter output: vulnerable,suspicious,nxdomain,alive")
	rootCmd.Flags().StringSliceVar(&exclude, "exclude", []string{}, "Exclude subdomains matching patterns (e.g. api,dev)")
	rootCmd.Flags().StringSliceVar(&include, "include", []string{}, "Only include subdomains matching patterns (e.g. shop,admin)")
	rootCmd.Flags().StringSliceVar(&matchSvc, "match", []string{}, "Only report specific services (e.g. heroku,github)")
	rootCmd.Flags().StringVar(&fpFile, "fingerprints", "", "Custom fingerprints JSON file")
	rootCmd.Flags().BoolVar(&verify, "verify", false, "Verify NXDOMAINs across multiple resolvers")
	rootCmd.Flags().BoolVar(&validate, "validate", false, "Run deep validation on suspicious/vulnerable findings")
	rootCmd.Flags().BoolVar(&verbose, "verbose", false, "Show dismissed candidates with reasons")

}