package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"sync"
)

const ChunkSize = 190

var PrivateKey *rsa.PrivateKey
var PublicKey []byte
var PeerPublicKeys sync.Map // Stores public keys of peers

func GenerateKeyPair() error {
	var err error
	PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	PublicKey = x509.MarshalPKCS1PublicKey(&PrivateKey.PublicKey)
	return nil
}

func EncryptMessageBatch(message string, peerKeyBytes []byte) ([][]byte, error) {
	peerKey, err := x509.ParsePKCS1PublicKey(peerKeyBytes)
	if err != nil {
		return nil, err
	}

	var chunks [][]byte
	for i := 0; i < len(message); i += ChunkSize {
		end := i + ChunkSize
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
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, PrivateKey, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}
