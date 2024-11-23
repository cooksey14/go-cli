package scanner

import (
	"strings"
)

// Simple service identification based on common port numbers and banners
func IdentifyService(portStatus PortStatus) string {
	port := portStatus.Port
	banner := strings.ToLower(portStatus.Banner)

	// Common services by port
	commonServices := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		3389: "RDP",
	}

	if service, exists := commonServices[port]; exists {
		return service
	}

	// Analyze banner for service identification
	if strings.Contains(banner, "http") {
		return "HTTP"
	}
	if strings.Contains(banner, "ssh") {
		return "SSH"
	}
	// Add more heuristics as needed

	return "Unknown"
}
