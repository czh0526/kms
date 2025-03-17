package sm2

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/test-go/testify/assert"
)

func TestGenerateSM2Key(t *testing.T) {
	privateKey, err := GenerateSM2Key()
	if err != nil {
		t.Fatalf("Failed to generate SM2 key: %v", err)
	}

	if privateKey == nil {
		t.Fatal("Generated SM2 key is nil")
	}

	publicKey := privateKey.PublicKey
	if publicKey.Curve == nil {
		t.Fatal("Public key curve is nil")
	}

	if publicKey.X == nil || publicKey.Y == nil {
		t.Fatal("Public key coordinates are nil")
	}
}

func TestSM2Key_Sign_Verify(t *testing.T) {
	privateKey, err := GenerateSM2Key()
	if err != nil {
		t.Fatalf("Failed to generate SM2 key: %v", err)
	}

	hash := sha256.Sum256([]byte("test"))
	signature, err := privateKey.Sign(rand.Reader, hash[:], nil)
	if err != nil {
		t.Fatalf("Failed to sign hash: %v", err)
	}

	valid := privateKey.Verify(hash[:], signature)
	assert.True(t, valid, "Signature should be valid")

	// Modify the hash to ensure the signature verification fails
	invalidHash := sha256.Sum256([]byte("invalid"))
	invalid := privateKey.Verify(invalidHash[:], signature)
	assert.False(t, invalid, "Signature should be invalid for a different hash")
}
