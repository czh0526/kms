package store

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
