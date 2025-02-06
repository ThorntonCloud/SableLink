package networking

import (
	"bufio"
	"fmt"
	"net"
	"os"

	"github.com/thorntoncloud/sable/internal/encryption"
)

func SendMessages(conn net.Conn, peerIP string) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("[You]: ")
		if scanner.Scan() {
			message := scanner.Text()
			peerKey, _ := encryption.PeerPublicKeys.Load(peerIP)
			if peerKey != nil {
				encryptedChunks, err := encryption.EncryptMessageBatch(message, peerKey.([]byte))
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
		decrypted, err := encryption.DecryptMessage(buffer[:n])
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
