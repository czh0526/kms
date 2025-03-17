package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"crypto/x509"
	"encoding/pem"
	"errors"
)

// GenerateECDSAKey 生成一个新的 EC 密钥对
func GenerateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func LoadPrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing EC private key")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil

}
