package keypair

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm2"
)

func TestNewKeyPairWithSM2Key(t *testing.T) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	keyPair, err := NewKeyPair(privateKey)
	assert.NoError(t, err)
	assert.NotNil(t, keyPair)
	assert.True(t, len(keyPair.Address) > 0)
	assert.True(t, len(keyPair.PrivateKey) > 0)
	assert.True(t, len(keyPair.PublicKey) > 0)
	assert.Contains(t, keyPair.Address, SM2_PREFIX)
}

func TestNewKeyPairWithECDSAKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	keyPair, err := NewKeyPair(privateKey)
	assert.NoError(t, err)
	assert.NotNil(t, keyPair)
	assert.True(t, len(keyPair.Address) > 0)
	assert.True(t, len(keyPair.PrivateKey) > 0)
	assert.True(t, len(keyPair.PublicKey) > 0)
	assert.Contains(t, keyPair.Address, ECDSA_PREFIX)
}

func TestNewKeyPairWithUnsupportedKey(t *testing.T) {
	_, err := NewKeyPair("unsupported key type")
	assert.Error(t, err)
	assert.Equal(t, "unsupported key type", err.Error())
}

func TestLoadKmsKeyWithSM2Key(t *testing.T) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	keyPair, err := NewKeyPair(privateKey)
	assert.NoError(t, err)

	kmsKey, err := keyPair.LoadKmsKey()
	assert.NoError(t, err)
	assert.NotNil(t, kmsKey)
}

func TestLoadKmsKeyWithECDSAKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	keyPair, err := NewKeyPair(privateKey)
	assert.NoError(t, err)

	kmsKey, err := keyPair.LoadKmsKey()
	assert.NoError(t, err)
	assert.NotNil(t, kmsKey)
}

func TestLoadKmsKeyWithUnsupportedKey(t *testing.T) {
	keyPair := &KeyPair{
		Address:    "unsupported-prefix-123",
		PrivateKey: "dummy-private-key",
		PublicKey:  "dummy-public-key",
	}

	_, err := keyPair.LoadKmsKey()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key address")
}
