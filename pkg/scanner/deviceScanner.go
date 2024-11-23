package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Device represents a device on the network
type Device struct {
	IP       string
	Hostname string
	MAC      string // Optional: Can be filled using ARP scan
}

// PingPort attempts to establish a TCP connection to the specified IP and port
func PingPort(ip string, port int, timeout time.Duration, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return
	}
	conn.Close()
	results <- ip
}

// PingSweep performs a ping sweep across the specified IP range
func PingSweep(ipRange []string, timeout time.Duration, concurrency int) []Device {
	var wg sync.WaitGroup
	results := make(chan string, len(ipRange))
	sem := make(chan struct{}, concurrency)

	for _, ip := range ipRange {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			// Attempt to connect to common ports to infer if the host is up
			ports := []int{80, 443, 22, 21, 23}
			var portWg sync.WaitGroup
			portResults := make(chan string, len(ports))
			for _, port := range ports {
				portWg.Add(1)
				go PingPort(ip, port, timeout, &portWg, portResults)
			}
			portWg.Wait()
			close(portResults)
			for range portResults {
				results <- ip
				return
			}
		}(ip)
	}

	wg.Wait()
	close(results)

	uniqueIPs := make(map[string]struct{})
	for ip := range results {
		uniqueIPs[ip] = struct{}{}
	}

	var devices []Device
	for ip := range uniqueIPs {
		hostname, err := net.LookupAddr(ip)
		if err != nil || len(hostname) == 0 {
			hostname = []string{"Unknown"}
		}
		devices = append(devices, Device{
			IP:       ip,
			Hostname: strings.TrimSuffix(hostname[0], "."),
		})
	}

	return devices
}

// GetLocalIPRange generates a list of IPs in the local network based on the provided interface's IP and subnet mask
func GetLocalIPRange(interfaceName string) ([]string, error) {
	if interfaceName == "" {
		return nil, fmt.Errorf("interface name is required")
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("could not find interface %s: %v", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("could not get addresses for interface %s: %v", interfaceName, err)
	}

	var ipNet *net.IPNet
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
			ipNet = v
		case *net.IPAddr:
			ip = v.IP
			ipNet = nil
		}
		if ip == nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		if ipNet == nil {
			continue
		}
		break
	}

	if ipNet == nil {
		return nil, fmt.Errorf("no valid IPv4 network found for interface %s", interfaceName)
	}

	// Calculate the number of hosts based on subnet mask
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	numHosts := 1 << hostBits

	// Generate IPs (excluding network and broadcast addresses)
	networkIP := ipNet.IP.Mask(ipNet.Mask)
	var ips []string
	for i := 1; i < numHosts-1; i++ { // Skip network and broadcast addresses
		tmp := make(net.IP, len(networkIP))
		copy(tmp, networkIP)
		for j := len(tmp) - 1; j >= 0; j-- {
			tmp[j] += byte(i)
			if tmp[j] != 0 {
				break
			}
		}
		ips = append(ips, tmp.String())
	}
	return ips, nil
}

// ARPScan scans the local network using ARP requests to discover devices
func ARPScan(interfaceName string, ipRange []string, timeout time.Duration) ([]Device, error) {
	handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever) // Set promiscuous to true
	if err != nil {
		return nil, fmt.Errorf("could not open device %s: %v", interfaceName, err)
	}
	defer handle.Close()

	srcMAC, srcIP, err := getInterfaceInfo(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("could not get interface info: %v", err)
	}

	var devices []Device
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Channel to signal when scanning is done
	done := make(chan struct{})

	// Start a goroutine to process incoming packets
	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp, _ := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply {
					ip := net.IP(arp.SourceProtAddress).String()
					mac := net.HardwareAddr(arp.SourceHwAddress).String()
					hostname, err := net.LookupAddr(ip)
					if err != nil || len(hostname) == 0 {
						hostname = []string{"Unknown"}
					}
					device := Device{
						IP:       ip,
						Hostname: strings.TrimSuffix(hostname[0], "."),
						MAC:      mac,
					}
					mu.Lock()
					devices = append(devices, device)
					mu.Unlock()
				}
			}
		}
		close(done)
	}()

	// Send ARP requests concurrently
	for _, ip := range ipRange {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			arpRequest := buildARPRequest(srcMAC, srcIP, ip)
			if err := handle.WritePacketData(arpRequest); err != nil {
				fmt.Printf("Failed to send ARP request to %s: %v\n", ip, err)
				return
			}
		}(ip)
	}

	// Wait for all ARP requests to be sent
	wg.Wait()

	// Wait for the timeout duration or until packet processing is done
	select {
	case <-done:
		// Packet processing finished before timeout
	case <-time.After(timeout):
		// Timeout reached, stop processing
		handle.Close() // This will stop the packetSource.Packets() iterator
	}

	return devices, nil
}

func getInterfaceInfo(interfaceName string) (net.HardwareAddr, net.IP, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get interface %s: %v", interfaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("could not get addresses for interface %s: %v", interfaceName, err)
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		return iface.HardwareAddr, ip, nil
	}
	return nil, nil, fmt.Errorf("no valid IP found for interface %s", interfaceName)
}

func buildARPRequest(srcMAC net.HardwareAddr, srcIP net.IP, dstIP string) []byte {
	dstMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(len(srcMAC)),
		ProtAddressSize:   uint8(len(srcIP)),
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(net.ParseIP(dstIP).To4()),
	}

	ethernet := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, opts, &ethernet, &arp)
	return buffer.Bytes()
}
