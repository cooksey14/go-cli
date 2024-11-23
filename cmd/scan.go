package cmd

import (
	"fmt"

	scanner "github.com/cooksey14/go-cli/pkg/scanner"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform a network scan",
	Long:  `Scan a target for open ports, identify services, and check for known vulnerabilities.`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		ports, _ := cmd.Flags().GetStringSlice("ports")

		if target == "" {
			fmt.Println("Please specify a target using -t or --target")
			return
		}

		scanner.RunScan(target, ports)
	},
}

func init() {
	scanCmd.Flags().StringP("target", "t", "", "Target to scan (e.g., example.com or IP)")
	scanCmd.Flags().StringSliceP("ports", "p", []string{"80", "443"}, "Ports to scan")
	scanCmd.MarkFlagRequired("target")
}
