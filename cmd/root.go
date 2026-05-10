package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
	"bufio"

	"github.com/spf13/cobra"
	"github.com/AliMousaviSoft/subjackal/internal/analyze"
	"github.com/AliMousaviSoft/subjackal/internal/enum"
	"github.com/AliMousaviSoft/subjackal/internal/model"
	"github.com/AliMousaviSoft/subjackal/internal/output"
	"github.com/AliMousaviSoft/subjackal/internal/pipeline"
	"github.com/AliMousaviSoft/subjackal/internal/probe"
	"github.com/AliMousaviSoft/subjackal/internal/resolve"
)

var (
	update     bool
	target     string
	targets    string
	threads    int
	timeoutMs  int
	jsonOutput bool
	outputFile string
	resolvers  []string
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
	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "Error: provide -target <domain> or -targets <file>")
		cmd.Help()
		os.Exit(1)
	}

	output.PrintBanner()

	// context with SIGINT/SIGTERM cancellation
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// build components
	resolver := resolve.New(resolvers, time.Duration(timeoutMs)*time.Millisecond, 3)
	analyzer := analyze.New(resolver)
	prober   := probe.New(5 * time.Second)
	crtsh    := enum.NewCrtSh()

	cfg := pipeline.Config{
		Threads:    threads,
		Resolver:   resolver,
		Analyzer:   analyzer,
		Prober:     prober,
		Enumerator: crtsh,
	}

	pipe := pipeline.New(cfg)

	// JSON writer (optional)
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

	// counters for summary
	counts := map[model.Status]int{}

	for _, domain := range domains {
		fmt.Printf("\n[*] Target: %s\n\n", domain)

		results := pipe.Run(ctx, domain)
		for sub := range results {
			output.PrintResult(sub)
			counts[sub.Status]++

			if jw != nil {
				jw.Write(sub)
			}
		}
	}

	// summary
	fmt.Printf("\n%s--- Summary ---%s\n", "\033[1m", "\033[0m")
	fmt.Printf("  Vulnerable  : %d\n", counts[model.StatusVulnerable])
	fmt.Printf("  Suspicious  : %d\n", counts[model.StatusSuspicious])
	fmt.Printf("  NXDOMAIN    : %d\n", counts[model.StatusNXDOMAIN])
	fmt.Printf("  Alive       : %d\n", counts[model.StatusAlive])
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
	rootCmd.Flags().BoolVarP(&update, "up", "", false, "Update to latest version")
	rootCmd.Flags().StringVarP(&target, "target", "", "", "Single target domain")
	rootCmd.Flags().StringVarP(&targets, "targets", "", "", "File with list of domains")
	rootCmd.Flags().IntVarP(&threads, "threads", "", 50, "Concurrency (default 50)")
	rootCmd.Flags().IntVarP(&timeoutMs, "timeout", "", 3000, "DNS timeout in ms (default 3000)")
	rootCmd.Flags().BoolVarP(&jsonOutput, "json", "", false, "JSON output to stdout")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write JSON results to file")
	rootCmd.Flags().StringSliceVarP(&resolvers, "resolvers", "r", []string{}, "Custom resolvers (e.g. 1.1.1.1:53,8.8.8.8:53)")
}