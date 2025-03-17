package store

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	kms_crypto "github.com/czh0526/kms/crypto"
	"github.com/mr-tron/base58"
	"github.com/tjfoc/gmsm/sm2"
	tjx509 "github.com/tjfoc/gmsm/x509"
)

type KeyPair struct {
	Address    string
	PrivateKey string
	PublicKey  string
}

const (
	SM2_PREFIX   = "sm2-"
	ECDSA_PREFIX = "ecc-"
)

func NewKeyPair(key any) (*KeyPair, error) {

	switch privateKey := key.(type) {
	case *sm2.PrivateKey:
		privateKeyBytes, err := tjx509.MarshalSm2PrivateKey(privateKey, nil)
		if err != nil {
			return nil, err
		}

		publicKeyBytes, err := tjx509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, err
		}

		address := fmt.Sprintf("%s%s", SM2_PREFIX, base58.Encode(privateKey.PublicKey.X.Bytes()))

		return &KeyPair{
			Address:    address,
			PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "SM2 PRIVATE KEY", Bytes: privateKeyBytes})),
			PublicKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})),
		}, nil

	case *ecdsa.PrivateKey:
		privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return nil, err
		}

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, err
		}

		address := fmt.Sprintf("%s%s", ECDSA_PREFIX, base58.Encode(privateKey.PublicKey.X.Bytes()))

		return &KeyPair{
			Address:    address,
			PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})),
			PublicKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})),
		}, nil

	}

	return nil, errors.New("unsupported key type")
}

func (kp *KeyPair) LoadKmsKey() (kms_crypto.KmsKey, error) {
	var keyType string
	if strings.HasPrefix(kp.Address, SM2_PREFIX) {
		keyType = kms_crypto.KeyType_SM2

	} else if strings.HasPrefix(kp.Address, ECDSA_PREFIX) {
		keyType = kms_crypto.KeyType_ECDSA

	} else {
		return nil, fmt.Errorf("unsupported key address: %v", kp.Address)
	}

	return kms_crypto.LoadKmsKey(keyType, []byte(kp.PrivateKey))
}
