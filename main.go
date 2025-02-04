package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	broadcastPort = ":9999" // UDP Port for discovery
	handshakePort = "8888"  // TCP Port for handshake
	chunkSize     = 190
)

var privateKey *rsa.PrivateKey
var publicKey []byte
var peerPublicKeys sync.Map // Stores public keys of peers

func generateKeyPair() error {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	publicKey = x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	return nil
}

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

func InitiateHandshake(peerIP string) {
	conn, err := net.Dial("tcp", peerIP+":"+handshakePort)
	if err != nil {
		fmt.Println("Handshake failed with", peerIP, "-", err)
		return
	}

	_, err = conn.Write(publicKey)
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
	peerPublicKeys.Store(peerIP, buffer[:n])
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

	peerPublicKeys.Store(conn.RemoteAddr().String(), buffer[:n])
	_, err = conn.Write(publicKey)
	if err != nil {
		fmt.Println("Error sending handshake acknowledgment:", err)
		conn.Close()
		return
	}

	fmt.Println("Handshake completed with", conn.RemoteAddr())
	go ChatSession(conn, conn.RemoteAddr().String())
}

func EncryptMessageBatch(message string, peerKeyBytes []byte) ([][]byte, error) {
	peerKey, err := x509.ParsePKCS1PublicKey(peerKeyBytes)
	if err != nil {
		return nil, err
	}

	var chunks [][]byte
	for i := 0; i < len(message); i += chunkSize {
		end := i + chunkSize
		if end > len(message) {
			end = len(message)
		}
		chunk := []byte(message[i:end])
		encryptedChunk, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, peerKey, chunk, nil)
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, encryptedChunk)
	}
	return chunks, nil
}

func DecryptMessage(ciphertext []byte) (string, error) {
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func SendMessages(conn net.Conn, peerIP string) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("[You]: ")
		if scanner.Scan() {
			message := scanner.Text()
			peerKey, _ := peerPublicKeys.Load(peerIP)
			if peerKey != nil {
				encryptedChunks, err := EncryptMessageBatch(message, peerKey.([]byte))
				if err == nil {
					for _, chunk := range encryptedChunks {
						conn.Write(chunk)
					}
				}
			}
		}
	}
}

func ReceiveMessages(conn net.Conn) {
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Println("Connection closed.")
			return
		}
		decrypted, err := DecryptMessage(buffer[:n])
		if err == nil {
			fmt.Println("\n[Peer]:", decrypted)
			fmt.Print("[You]: ")
		}
	}
}

func ChatSession(conn net.Conn, peerIP string) {
	fmt.Println("Chat session established with", peerIP)
	go ReceiveMessages(conn)
	SendMessages(conn, peerIP)
}

func main() {
	if err := generateKeyPair(); err != nil {
		fmt.Println("Error generating keys:", err)
		return
	}

	localIP, err := GetLocalIP()
	if err != nil {
		fmt.Println("Error getting local IP:", err)
		return
	}

	fmt.Println("Local IP:", localIP)
	go ListenForPeers(localIP)
	go ListenForHandshakes()
	time.Sleep(2 * time.Second)
	BroadcastPresence(localIP)

	select {}
}
