package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortStatus struct {
	Port   int
	Open   bool
	Banner string
}

func ScanPort(target string, port int, timeout time.Duration, wg *sync.WaitGroup, results chan<- PortStatus) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		results <- PortStatus{Port: port, Open: false}
		return
	}
	defer conn.Close()

	// Set a deadline for reading
	conn.SetDeadline(time.Now().Add(timeout))

	// Attempt to read banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	banner := ""
	if err == nil && n > 0 {
		banner = string(buffer[:n])
	}

	results <- PortStatus{Port: port, Open: true, Banner: banner}
}

func PortScan(target string, ports []int) []PortStatus {
	var wg sync.WaitGroup
	results := make(chan PortStatus, len(ports))
	timeout := 2 * time.Second

	for _, port := range ports {
		wg.Add(1)
		go ScanPort(target, port, timeout, &wg, results)
	}

	wg.Wait()
	close(results)

	var openPorts []PortStatus
	for result := range results {
		if result.Open {
			openPorts = append(openPorts, result)
		}
	}
	return openPorts
}

func GetPortsFromSlice(ports []string) []int {
	var portInts []int
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if strings.Contains(p, "-") {
			// Handle range
			var start, end int
			_, err := fmt.Sscanf(p, "%d-%d", &start, &end)
			if err != nil {
				continue
			}
			for i := start; i <= end; i++ {
				portInts = append(portInts, i)
			}
		} else {
			port, err := strconv.Atoi(p)
			if err == nil {
				portInts = append(portInts, port)
			}
		}
	}
	return portInts
}

func RunScan(target string, ports []string) {
	portInts := GetPortsFromSlice(ports)
	fmt.Printf("Starting scan on %s...\n", target)
	openPorts := PortScan(target, portInts)
	if len(openPorts) == 0 {
		fmt.Println("No open ports found.")
		return
	}

	for _, portStatus := range openPorts {
		service := IdentifyService(portStatus)
		vulns := CheckVulnerabilities(service, portStatus.Banner)
		fmt.Printf("Port %d Open\n", portStatus.Port)
		fmt.Printf("Service: %s\n", service)
		if len(vulns) > 0 {
			for _, vuln := range vulns {
				fmt.Printf("Vulnerability: %s\n", vuln.CVE)
				fmt.Printf("Description: %s\n", vuln.Description)
			}
		}
		fmt.Println("---------------------------")
	}
}
