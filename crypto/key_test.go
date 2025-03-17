package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
)

func TestSign_ECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	key, err := NewKmsKey(KeyType_ECDSA, privKey)
	if err != nil {
		t.Fatalf("Failed to create Key: %v", err)
	}

	data := []byte("test data")
	signature, err := key.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	if len(signature) == 0 {
		t.Fatalf("Expected non-empty signature")
	}
}

func TestSign_SM2(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate SM2 key: %v", err)
	}

	key, err := NewKmsKey(KeyType_SM2, privKey)
	if err != nil {
		t.Fatalf("Failed to create Key: %v", err)
	}

	data := []byte("test data")
	signature, err := key.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	if len(signature) == 0 {
		t.Fatalf("Expected non-empty signature")
	}
}

func TestSign_UnsupportedKeyType(t *testing.T) {
	key := &Key{KeyType: "Unsupported"}
	data := []byte("test data")
	_, err := key.Sign(data)
	if err == nil {
		t.Fatalf("Expected error for unsupported key type")
	}
}
