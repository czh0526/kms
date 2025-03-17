package sm2

import (
	"crypto/rand"
	"encoding/pem"
	"errors"

	"github.com/tjfoc/gmsm/sm2"
	tjx509 "github.com/tjfoc/gmsm/x509"
)

// GenerateSM2Key 生成一个新的 SM2 密钥对
func GenerateSM2Key() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

// LoadPrivateKey 从 PEM 格式的字符串中加载 SM2 私钥
func LoadPrivateKey(pemData []byte) (*sm2.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "SM2 PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := tjx509.ParsePKCS8UnecryptedPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
