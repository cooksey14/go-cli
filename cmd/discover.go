package cmd

import (
	"fmt"
	"os"
	"time"

	scanner "github.com/cooksey14/go-cli/pkg/scanner"
	"github.com/spf13/cobra"
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover devices on the local network",
	Long:  `Discover devices connected to the local network using Ping Sweep or ARP Scan methods.`,
	Run: func(cmd *cobra.Command, args []string) {
		method, _ := cmd.Flags().GetString("method")
		concurrency, _ := cmd.Flags().GetInt("concurrency")
		timeout, _ := cmd.Flags().GetInt("timeout")
		iface, _ := cmd.Flags().GetString("interface")

		// Pass the interface name to GetLocalIPRange
		ipRange, err := scanner.GetLocalIPRange(iface)
		if err != nil {
			fmt.Println("Error getting local IP range:", err)
			os.Exit(1)
		}

		fmt.Println("Starting device discovery...")
		var devices []scanner.Device

		switch method {
		case "ping":
			devices = scanner.PingSweep(ipRange, time.Duration(timeout)*time.Second, concurrency)
		case "arp":
			if iface == "" {
				fmt.Println("Please specify the network interface using --interface for ARP scan.")
				os.Exit(1)
			}
			devices, err = scanner.ARPScan(iface, ipRange, time.Duration(timeout)*time.Second)
			if err != nil {
				fmt.Println("Error performing ARP scan:", err)
				os.Exit(1)
			}
		default:
			fmt.Println("Unknown discovery method. Use 'ping' or 'arp'.")
			os.Exit(1)
		}

		if len(devices) == 0 {
			fmt.Println("No devices found.")
			return
		}

		fmt.Println("Devices Found:")
		for _, device := range devices {
			fmt.Printf("IP: %s | Hostname: %s | MAC: %s\n", device.IP, device.Hostname, device.MAC)
		}
	},
}

func init() {
	rootCmd.AddCommand(discoverCmd)

	discoverCmd.Flags().StringP("method", "m", "ping", "Discovery method: ping or arp")
	discoverCmd.Flags().IntP("concurrency", "c", 100, "Number of concurrent probes")
	discoverCmd.Flags().IntP("timeout", "t", 2, "Timeout in seconds for each probe")
	discoverCmd.Flags().StringP("interface", "i", "", "Network interface for ARP scan (required for arp method)")
}
