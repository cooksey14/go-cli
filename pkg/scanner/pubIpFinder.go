package scanner

import (
	"encoding/json"
	"net/http"
	"time"
)

// PublicIP represents the response from an external service
type PublicIP struct {
	IP string `json:"ip"`
}

// GetPublicIP retrieves the public IP of the network by querying an external service
func GetPublicIP() (string, error) {
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var ip PublicIP
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&ip); err != nil {
		return "", err
	}
	return ip.IP, nil
}
