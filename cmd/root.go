package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var update bool

var rootCmd = &cobra.Command{
	Use:   "subjackal",
	Short: "Subdomain takeover hunter",
	Run: func(cmd *cobra.Command, args []string) {
		if update {
			fmt.Println("Updating subjackal...")
			c := exec.Command("go", "install", "-v", "github.com/AliMousaviSoft/subjackal@latest")
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			if err := c.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Updated successfully.")
			return
		}
		cmd.Help()
	},
}

func Execute() {
	rootCmd.Execute()
}

func init() {
	rootCmd.Flags().BoolVarP(&update, "up", "", false, "Update subjackal to latest version")
}