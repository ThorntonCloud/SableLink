package main

import (
	"fmt"
	"time"

	"github.com/thorntoncloud/sable/internal/encryption"
	"github.com/thorntoncloud/sable/internal/networking"
	"github.com/thorntoncloud/sable/internal/utils"
)

func main() {
	if err := encryption.GenerateKeyPair(); err != nil {
		fmt.Println("Error generating keys:", err)
		return
	}

	localIP, err := utils.GetLocalIP()
	if err != nil {
		fmt.Println("Error getting local IP:", err)
		return
	}

	fmt.Println("Local IP:", localIP)
	go networking.ListenForPeers(localIP)
	go networking.ListenForHandshakes()
	time.Sleep(2 * time.Second)
	networking.BroadcastPresence(localIP)

	select {}
}
