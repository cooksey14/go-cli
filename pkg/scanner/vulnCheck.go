package scanner

import (
    "strings"
)

// Simple vulnerability definitions
type Vulnerability struct {
    Service     string
    Version     string
    CVE         string
    Description string
}

var knownVulnerabilities = []Vulnerability{
    {
        Service:     "SSH",
        Version:     "OpenSSH 7.2",
        CVE:         "CVE-2016-0777",
        Description: "Buffer overflow vulnerability in OpenSSH 7.2.",
    },
    // Add more vulnerabilities as needed
}

func CheckVulnerabilities(service string, banner string) []Vulnerability {
    var vulns []Vulnerability
    for _, vuln := range knownVulnerabilities {
        if strings.Contains(strings.ToLower(service), strings.ToLower(vuln.Service)) &&
            strings.Contains(strings.ToLower(banner), strings.ToLower(vuln.Version)) {
            vulns = append(vulns, vuln)
        }
    }
    return vulns
}
