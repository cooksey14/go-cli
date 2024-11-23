
# Go-CLI: Network Discovery & Vulnerability Scanner

![Go](https://img.shields.io/badge/Go-1.23.3-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Go-CLI is a command-line tool built with Go for discovering devices on your local network and scanning your network's public IP for vulnerabilities. Ideal for network administrators, and security professionals.

## 🛠 Features

- **Device Discovery:**
  - **Ping Sweep:** Identify active devices by sending ICMP echo requests.
  - **ARP Scan:** Discover devices using ARP requests for reliable local network results.

- **Public IP Scanning:**
  - Retrieve your network's public IP address.
  - Scan open ports to identify services and potential vulnerabilities.

- **Customizable Scans:**
  - Control concurrency levels for efficient scanning.
  - Set timeouts to balance speed and thoroughness.

## 📦 Installation

### Prerequisites

- **Go:** Version 1.22 or later. Download from [Go's official website](https://golang.org/dl/).

### Build from Source

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/go-cli.git
   cd go-cli
   ```

2. **Download Dependencies:**

   ```bash
   go mod tidy
   ```

3. **Build the Executable:**

   ```bash
   go build -o go-cli
   ```

## 🚀 Usage

### 1. Discover Devices on the Local Network

#### a. Ping Sweep

Quickly identify active devices using ICMP echo requests.

```bash
./go-cli discover --method ping --concurrency 100 --timeout 5 --interface $INTERFACE
```

**Flags:**

- `--method, -m`: Discovery method (`ping` or `arp`). Default: `ping``
- `--timeout, -t`: Timeout in seconds. Default: `2`
- `--interface, -i`: Network interface to use.

#### b. ARP Scan

Discover devices by sending ARP requests for more reliable local network results.

```bash
sudo ./go-cli discover --method arp --interface $INTERFACE --timeout 5
```

**Flags:**

- `--method, -m`: Discovery method (`ping` or `arp`)
- `--interface, -i`: **Required** for ARP scan.
- `--timeout, -t`: Timeout in seconds. Default: `2`
- `--concurrency, -c`: Number of concurrent probes. Default: `100
- `--ports, -p`: Comma-separated list of ports (supports ranges, e.g., `20-25`).

### 2. Scan the Public IP for Vulnerabilities

Identify open ports and potential vulnerabilities on your public-facing IP.

```bash
./go-cli discover --method arp --interface $INTERFACE --timeout 2
```


### 3. Scan a Specific Target

Perform a vulnerability scan on a specified domain or IP address.

```bash
./go-cli scan --target example.com --ports 22,80,443
```

**Flags:**

- `--target, -t`: Target to scan (e.g., `example.com` or IP).
- `--ports, -p`: Comma-separated list of ports.

## 📋 Examples

- **ARP Scan on `en0` with 5-second timeout:**

  ```bash
  sudo ./go-cli discover --method arp --interface en0 --timeout 5
  ```

- **Ping Sweep with Default Settings:**

  ```bash
  ./go-cli discover --method ping --interface en0
  ```

- **Scan Public IP for Common Ports:**

  ```bash
  ./go-cli scan --public --ports 80,443,22
  ```

- **Scan Specific IP for Port Range:**

  ```bash
  ./go-cli scan --target 192.168.86.1 --ports 20-25
  ```

## 📦 Dependencies

- [`github.com/spf13/cobra`](https://github.com/spf13/cobra): CLI framework.
- [`github.com/google/gopacket`](https://github.com/google/gopacket): Packet processing for ARP scans.
- [`github.com/google/gopacket/pcap`](https://github.com/google/gopacket/pcap): Network interface interactions.

## 🤝 Contributing

Contributions are welcome! Follow these steps:

1. **Fork the Repository**
2. **Create a New Branch:**

   ```bash
   git checkout -b feature/YourFeature
   ```

3. **Commit Your Changes:**

   ```bash
   git commit -m "Add YourFeature"
   ```

4. **Push to the Branch:**

   ```bash
   git push origin feature/YourFeature
   ```

5. **Open a Pull Request**

Ensure your contributions adhere to the project's coding standards and include relevant tests.

## 📝 License

This project is licensed under the [MIT License](LICENSE).

---

**Disclaimer:** Use Go-CLI responsibly and ensure you have proper authorization to scan networks and devices.
