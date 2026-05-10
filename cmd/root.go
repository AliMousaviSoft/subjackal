package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

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
	update     bool
	target     string
	targets    string
	subs       string
	threads    int
	timeoutMs  int
	jsonOutput bool
	outputFile string
	resolvers  []string
	silent     bool
	debug      bool
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

	domains := collectDomains()
	if len(domains) == 0 && subs == "" {
		fmt.Fprintln(os.Stderr, "Error: provide --target, --targets, or --subs")
		cmd.Help()
		os.Exit(1)
	}

	if !silent {
		output.PrintBanner()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// pick enumerator: --subs file takes priority over crt.sh
	var enumerator enum.Enumerator
	if subs != "" {
		enumerator = enum.NewFileEnum(subs)
	} else {
		enumerator = enum.NewCrtSh()
	}

	// debug mode: test enumeration only
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

	resolver := resolve.New(resolvers, time.Duration(timeoutMs)*time.Millisecond, 3)
	analyzer := analyze.New(resolver)
	prober   := probe.New(5 * time.Second)

	cfg := pipeline.Config{
		Threads:    threads,
		Resolver:   resolver,
		Analyzer:   analyzer,
		Prober:     prober,
		Enumerator: enumerator,
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

	// if --subs given, use a dummy domain label (not used for filtering)
	runDomains := domains
	if subs != "" && len(runDomains) == 0 {
		runDomains = []string{""}
	}

	for _, domain := range runDomains {
		if !silent {
			if subs != "" {
				fmt.Printf("\n[*] Mode: file-based (%s)\n\n", subs)
			} else {
				fmt.Printf("\n[*] Target: %s\n\n", domain)
			}
		}

		results := pipe.Run(ctx, domain)
		for sub := range results {
			counts[sub.Status]++

			if jw != nil {
				jw.Write(sub)
			}

			if !silent {
				output.PrintResult(sub, silent)
			}
		}
	}

	if !silent {
		fmt.Printf("\n%s--- Summary ---%s\n", "\033[1m", "\033[0m")
		fmt.Printf("  Vulnerable  : %d\n", counts[model.StatusVulnerable])
		fmt.Printf("  Suspicious  : %d\n", counts[model.StatusSuspicious])
		fmt.Printf("  NXDOMAIN    : %d\n", counts[model.StatusNXDOMAIN])
		fmt.Printf("  Alive       : %d\n", counts[model.StatusAlive])
	}
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
	rootCmd.Flags().IntVar(&threads, "threads", 50, "Concurrency (default 50)")
	rootCmd.Flags().IntVar(&timeoutMs, "timeout", 3000, "DNS timeout in ms (default 3000)")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "JSON output to stdout")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write JSON results to file")
	rootCmd.Flags().StringSliceVarP(&resolvers, "resolvers", "r", []string{}, "Custom resolvers (e.g. 1.1.1.1:53,8.8.8.8:53)")
	rootCmd.Flags().BoolVar(&silent, "silent", false, "Suppress terminal output, only write to -o file")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "Debug mode: test enumeration only")
}