package networking

import (
	"fmt"
	"net"

	"github.com/thorntoncloud/sablelink/internal/encryption"
)

func InitiateHandshake(peerIP string) {
	conn, err := net.Dial("tcp", peerIP+":"+handshakePort)
	if err != nil {
		fmt.Println("Handshake failed with", peerIP, "-", err)
		return
	}

	_, err = conn.Write(encryption.PublicKey)
	if err != nil {
		fmt.Println("Error sending handshake message:", err)
		conn.Close()
		return
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("No response from", peerIP)
		conn.Close()
		return
	}
	encryption.PeerPublicKeys.Store(peerIP, buffer[:n])
	fmt.Println("Handshake successful with", peerIP)
	go ChatSession(conn, peerIP)
}

func ListenForHandshakes() {
	ln, err := net.Listen("tcp", ":"+handshakePort)
	if err != nil {
		fmt.Println("Error starting handshake listener:", err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting handshake connection:", err)
			continue
		}
		go HandleHandshake(conn)
	}
}

func HandleHandshake(conn net.Conn) {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading handshake message:", err)
		conn.Close()
		return
	}

	encryption.PeerPublicKeys.Store(conn.RemoteAddr().String(), buffer[:n])
	_, err = conn.Write(encryption.PublicKey)
	if err != nil {
		fmt.Println("Error sending handshake acknowledgment:", err)
		conn.Close()
		return
	}

	fmt.Println("Handshake completed with", conn.RemoteAddr())
	go ChatSession(conn, conn.RemoteAddr().String())
}
