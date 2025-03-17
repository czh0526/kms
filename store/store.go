package store

import (
	"fmt"

	"github.com/czh0526/kms/config"
)

type KeyStore struct {
	cfg   *config.Config
	store Store
}

func NewKeyStore(cfg *config.Config) (*KeyStore, error) {
	var store Store
	switch cfg.StoreType {
	case "FileStore":
		if cfg.FileStore == nil {
			return nil, fmt.Errorf("missing FileStore config")
		}
		store = NewFileStore(cfg.FileStore.Path)

	case "DbStore":
		if cfg.DbStore == nil {
			return nil, fmt.Errorf("missing DbStore config")
		}
		store = NewDBStore(cfg.DbStore.DSN)

	default:
		return nil, fmt.Errorf("unknown store type: %s", cfg.StoreType)
	}

	return &KeyStore{
		cfg:   cfg,
		store: store,
	}, nil
}
