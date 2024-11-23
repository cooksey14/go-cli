package scanner

import (
	"fmt"
)

// VulnerabilityReport represents the vulnerabilities found on a target
type VulnerabilityReport struct {
	Target          string
	OpenPorts       []PortStatus
	Vulnerabilities map[string][]Vulnerability // Keyed by port
}

// ScanPublicIP performs a vulnerability scan on the public IP
func ScanPublicIP(publicIP string, ports []string) VulnerabilityReport {
	portInts := GetPortsFromSlice(ports)
	openPorts := PortScan(publicIP, portInts)
	vulnMap := make(map[string][]Vulnerability)

	for _, portStatus := range openPorts {
		service := IdentifyService(portStatus)
		vulns := CheckVulnerabilities(service, portStatus.Banner)
		if len(vulns) > 0 {
			vulnMap[fmt.Sprintf("%d", portStatus.Port)] = vulns
		}
	}

	return VulnerabilityReport{
		Target:          publicIP,
		OpenPorts:       openPorts,
		Vulnerabilities: vulnMap,
	}
}
