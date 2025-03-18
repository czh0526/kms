package store

import (
	"fmt"

	"github.com/czh0526/kms/config"
	kms_db "github.com/czh0526/kms/store/db"
	kms_file "github.com/czh0526/kms/store/file"
	"github.com/czh0526/kms/store/keypair"
)

type KeyStore struct {
	cfg   *config.Config
	store Store
}

func NewKeyStore(cfg *config.Config) (*KeyStore, error) {
	var store Store
	var err error

	switch cfg.StoreType {
	case "FileStore":
		if cfg.FileStore == nil {
			return nil, fmt.Errorf("missing FileStore config")
		}
		store = kms_file.NewFileStore(cfg.FileStore.Path)

	case "DbStore":
		if cfg.DbStore == nil {
			return nil, fmt.Errorf("missing DbStore config")
		}
		store, err = kms_db.NewDBStore(cfg.DbStore.DSN)
		if err != nil {
			return nil, fmt.Errorf("failed to create DbStore: %v", err)
		}

	default:
		return nil, fmt.Errorf("unknown store type: %s", cfg.StoreType)
	}

	return &KeyStore{
		cfg:   cfg,
		store: store,
	}, nil
}

func (ks *KeyStore) Save(keyPair *keypair.KeyPair) error {
	return ks.store.Save(keyPair)
}

func (ks *KeyStore) Load(address string) (*keypair.KeyPair, error) {
	return ks.store.Load(address)
}

func (ks *KeyStore) Delete(address string) error {
	return ks.store.Delete(address)
}
