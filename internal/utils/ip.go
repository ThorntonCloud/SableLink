package utils

import (
	"fmt"
	"net"
	"strings"
)

func GetLocalIP() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip.IsGlobalUnicast() && !strings.HasPrefix(ip.String(), "169.254.") {
				return ip.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no valid local IP found")
}
