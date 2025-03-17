package store

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/czh0526/kms/key"
)

func TestFileStore(t *testing.T) {
	dir, err := ioutil.TempDir("", "keystore")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	store := NewFileStore(dir)

	keyPair := &key.KeyPair{
		Address:    "test_address",
		PrivateKey: "test_private_key",
		PublicKey:  "test_public_key",
	}

	// Test Save
	if err := store.Save(keyPair); err != nil {
		t.Fatalf("Failed to save key pair: %v", err)
	}

	// Test Load
	loadedKeyPair, err := store.Load("test_address")
	if err != nil {
		t.Fatalf("Failed to load key pair: %v", err)
	}

	if loadedKeyPair.Address != keyPair.Address {
		t.Errorf("Expected Address %s, got %s", keyPair.Address, loadedKeyPair.Address)
	}
	if loadedKeyPair.PrivateKey != keyPair.PrivateKey {
		t.Errorf("Expected PrivateKey %s, got %s", keyPair.PrivateKey, loadedKeyPair.PrivateKey)
	}
	if loadedKeyPair.PublicKey != keyPair.PublicKey {
		t.Errorf("Expected PublicKey %s, got %s", keyPair.PublicKey, loadedKeyPair.PublicKey)
	}
}
