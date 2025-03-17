package store

type Store interface {
	Save(keyPair *KeyPair) error
	Load(address string) (*KeyPair, error)
	Delete(address string) error
}
