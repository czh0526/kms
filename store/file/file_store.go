package store

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/czh0526/kms/store/keypair"
)

// FileStore 实现 Store 接口
type FileStore struct {
	directory string
}

// NewFileStore 创建一个新的 FileStore
func NewFileStore(directory string) *FileStore {
	return &FileStore{directory: directory}
}

// Save 保存密钥对到文件
func (s *FileStore) Save(keyPair *keypair.KeyPair) error {
	data, err := json.Marshal(keyPair)
	if err != nil {
		return err
	}

	filePath := filepath.Join(s.directory, fmt.Sprintf("%s.json", keyPair.Address))
	return ioutil.WriteFile(filePath, data, 0644)
}

// Load 从文件加载密钥对
func (s *FileStore) Load(address string) (*keypair.KeyPair, error) {
	filePath := filepath.Join(s.directory, fmt.Sprintf("%s.json", address))
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var keyPair keypair.KeyPair
	if err := json.Unmarshal(data, &keyPair); err != nil {
		return nil, err
	}

	return &keyPair, nil
}

// Delete 从文件删除密钥对
func (s *FileStore) Delete(address string) error {
	filePath := filepath.Join(s.directory, fmt.Sprintf("%s.json", address))
	return os.Remove(filePath)
}
