package store

import (
	"testing"

	"github.com/czh0526/kms/key"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestDBStore(t *testing.T) {
	dsn := "root:123456@tcp(localhost:3306)/kms_db?parseTime=true&loc=Local&time_zone=%27%2B08%3A00%27"
	store := NewDBStore(dsn)

	// Initialize the database connection
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto migrate the KeyPair model
	db.AutoMigrate(&KeyPair{})

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

	// Test Delete
	if err := store.Delete("test_address"); err != nil {
		t.Fatalf("Failed to delete key pair: %v", err)
	}

	// Verify deletion
	_, err = store.Load("test_address")
	if err == nil {
		t.Fatalf("Expected error when loading deleted key pair, got nil")
	}
}
