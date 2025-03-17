package store

import (
	"fmt"
)

type MockStore struct {
	KeyPairs map[string]*KeyPair
}

func NewMockStore() *MockStore {
	return &MockStore{
		KeyPairs: make(map[string]*KeyPair),
	}
}

func (m *MockStore) Save(keyPair *KeyPair) error {
	m.KeyPairs[keyPair.Address] = keyPair
	return nil
}

func (m *MockStore) Load(address string) (*KeyPair, error) {
	keyPair, exists := m.KeyPairs[address]
	if !exists {
		return nil, fmt.Errorf("key pair not found")
	}
	return keyPair, nil
}

func (m *MockStore) Delete(address string) error {
	delete(m.KeyPairs, address)
	return nil
}
