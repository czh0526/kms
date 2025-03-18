package store

import "github.com/czh0526/kms/store/keypair"

type Store interface {
	Save(keyPair *keypair.KeyPair) error
	Load(address string) (*keypair.KeyPair, error)
	Delete(address string) error
}
