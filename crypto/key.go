package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	kms_ecdsa "github.com/czh0526/kms/crypto/ecdsa"
	kms_sm2 "github.com/czh0526/kms/crypto/sm2"
	"github.com/tjfoc/gmsm/sm2"
)

type KmsKey interface {
	Sign(data []byte) ([]byte, error)
	Verify(data []byte, signature []byte) (bool, error)
}

const (
	KeyType_ECDSA = "ECDSA"
	KeyType_SM2   = "SM2"
)

type Key struct {
	KeyType string
	ecKey   *ecdsa.PrivateKey
	sm2Key  *sm2.PrivateKey
}

func NewKmsKey(keyType string, key any) (*Key, error) {
	switch keyType {
	case KeyType_ECDSA:
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("invalid key type: ECDSA")
		}
		return &Key{
			KeyType: KeyType_ECDSA,
			ecKey:   ecKey,
		}, nil

	case KeyType_SM2:
		sm2Key, ok := key.(*sm2.PrivateKey)
		if !ok {
			return nil, errors.New("invalid key type: SM2")
		}
		return &Key{
			KeyType: KeyType_SM2,
			sm2Key:  sm2Key,
		}, nil
	}

	return nil, fmt.Errorf("unsupported key type: %v", keyType)
}

func LoadKmsKey(keyType string, pemData []byte) (KmsKey, error) {
	var err error

	switch keyType {
	case KeyType_ECDSA:
		var ecPrivateKey *ecdsa.PrivateKey
		if ecPrivateKey, err = kms_ecdsa.LoadPrivateKey(pemData); err != nil {
			return nil, fmt.Errorf("failed to load ECDSA key, err = %v", err)
		}

		return NewKmsKey(KeyType_ECDSA, ecPrivateKey)

	case KeyType_SM2:
		var sm2PrivateKey *sm2.PrivateKey
		if sm2PrivateKey, err = kms_sm2.LoadPrivateKey(pemData); err != nil {
			return nil, fmt.Errorf("failed to load SM2 key, err = %v", err)
		}

		return NewKmsKey(KeyType_SM2, sm2PrivateKey)
	}

	return nil, fmt.Errorf("unsupported key type: %v", keyType)
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (k *Key) Sign(data []byte) ([]byte, error) {
	switch k.KeyType {
	case KeyType_ECDSA:
		r, s, err := ecdsa.Sign(rand.Reader, k.ecKey, data)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(ecdsaSignature{r, s})
	case KeyType_SM2:
		return k.sm2Key.Sign(rand.Reader, data, nil)
	default:
		return nil, fmt.Errorf("unsupported key type: %v", k.KeyType)
	}
}

func (k *Key) Verify(data []byte, signature []byte) (bool, error) {
	switch k.KeyType {
	case KeyType_ECDSA:
		var sig ecdsaSignature
		_, err := asn1.Unmarshal(signature, &sig)
		if err != nil {
			return false, err
		}
		return ecdsa.Verify(&k.ecKey.PublicKey, data, sig.R, sig.S), nil
	case KeyType_SM2:
		return k.sm2Key.Verify(data, signature), nil
	default:
		return false, fmt.Errorf("unsupported key type: %v", k.KeyType)
	}
}
