package store

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/czh0526/kms/crypto"
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
	var privateKeyBytes []byte
	var publicKeyBytes []byte
	var address string
	var err error

	switch privateKey := key.(type) {
	case *sm2.PrivateKey:
		privateKeyBytes, err = tjx509.MarshalSm2PrivateKey(privateKey, nil)
		if err != nil {
			return nil, err
		}

		publicKeyBytes, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, err
		}

		address = fmt.Sprintf("%s%s", SM2_PREFIX, base58.Encode(privateKey.PublicKey.X.Bytes()))

	case *ecdsa.PrivateKey:
		privateKeyBytes, err = x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return nil, err
		}

		publicKeyBytes, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, err
		}

		address = fmt.Sprintf("%s%s", ECDSA_PREFIX, base58.Encode(privateKey.PublicKey.X.Bytes()))

	default:
		return nil, errors.New("unsupported key type")
	}

	return &KeyPair{
		Address:    address,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})),
		PublicKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})),
	}, nil
}

func (kp *KeyPair) LoadAsymKey() (crypto.AsymKey, error) {
	if strings.HasPrefix(kp.Address, SM2_PREFIX) {
		return kms_crypto.LoadSM2Key([]byte(kp.PrivateKey))

	} else if strings.HasPrefix(kp.Address, ECDSA_PREFIX) {
		return kms_crypto.LoadECDSAKey([]byte(kp.PrivateKey))
	}

	return nil, fmt.Errorf("unsupported key type: %v", kp.Address)
}
