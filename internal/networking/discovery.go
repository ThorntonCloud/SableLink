package networking

import (
	"fmt"
	"net"
	"strings"
)

const (
	broadcastPort = ":9999" // UDP Port for discovery
	handshakePort = "8888"  // TCP Port for handshake
)

func BroadcastPresence(localIP string) {
	conn, err := net.Dial("udp", "255.255.255.255"+broadcastPort)
	if err != nil {
		fmt.Println("Error broadcasting:", err)
		return
	}
	defer conn.Close()
	_, err = conn.Write([]byte(localIP))
	if err != nil {
		fmt.Println("Error sending broadcast:", err)
	}
}

func ListenForPeers(localIP string) {
	addr, err := net.ResolveUDPAddr("udp", broadcastPort)
	if err != nil {
		fmt.Println("Error resolving UDP address:", err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("Error listening for peers:", err)
		return
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error reading UDP message:", err)
			continue
		}
		peerIP := strings.TrimSpace(string(buf[:n]))
		if peerIP != localIP {
			fmt.Println("Discovered peer:", peerIP)
			go InitiateHandshake(peerIP)
		}
	}
}
