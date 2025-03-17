package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/test-go/testify/assert"
)

func TestGenerateECDSAKey(t *testing.T) {
	privateKey, err := GenerateECDSAKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	if privateKey == nil {
		t.Fatal("Generated ECDSA key is nil")
	}

	publicKey := privateKey.PublicKey
	if publicKey.Curve == nil {
		t.Fatal("Public key curve is nil")
	}

	if publicKey.X == nil || publicKey.Y == nil {
		t.Fatal("Public key coordinates are nil")
	}
}

func TestECDSAKey_Sign_Verify(t *testing.T) {
	privateKey, err := GenerateECDSAKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	hash := sha256.Sum256([]byte("test"))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign hash: %v", err)
	}

	valid := ecdsa.Verify(&privateKey.PublicKey, hash[:], r, s)
	assert.True(t, valid, "Signature should be valid")

	// Modify the hash to ensure the signature verification fails
	invalidHash := sha256.Sum256([]byte("invalid"))
	invalid := ecdsa.Verify(&privateKey.PublicKey, invalidHash[:], r, s)
	assert.False(t, invalid, "Signature should be invalid for a different hash")
}
