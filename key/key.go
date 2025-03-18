package key

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

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

func NewKey(keyType string, key any) (*Key, error) {
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
