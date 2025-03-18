package db

import (
	"fmt"
	"sync"

	"github.com/czh0526/kms/store/db/model"
	"github.com/czh0526/kms/store/keypair"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// DBStore 实现 Store 接口
type DBStore struct {
	dsn string
	db  *gorm.DB
	mu  sync.Mutex
}

// NewDBStore 创建一个新的 DBStore
func NewDBStore(dsn string) (*DBStore, error) {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	return &DBStore{dsn: dsn, db: db}, nil
}

// Save 保存密钥对到数据库
func (s *DBStore) Save(keyPair *keypair.KeyPair) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 自动迁移模式
	s.db.AutoMigrate(&model.KeyPair{})

	modelKeyPair := model.KeyPair{
		Address:    keyPair.Address,
		PrivateKey: keyPair.PrivateKey,
		PublicKey:  keyPair.PublicKey,
	}
	if err := s.db.Create(&modelKeyPair).Error; err != nil {
		return err
	}

	fmt.Println("密钥对已保存到数据库")
	return nil
}

// Load 从数据库加载密钥对
func (s *DBStore) Load(address string) (*keypair.KeyPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var modelKeyPair model.KeyPair
	if err := s.db.First(&modelKeyPair, "address = ?", address).Error; err != nil {
		return nil, err
	}

	return &keypair.KeyPair{
		Address:    modelKeyPair.Address,
		PrivateKey: modelKeyPair.PrivateKey,
		PublicKey:  modelKeyPair.PublicKey,
	}, nil
}

// Delete 从数据库删除密钥对
func (s *DBStore) Delete(address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.db.Delete(&model.KeyPair{}, "address = ?", address).Error; err != nil {
		return err
	}

	fmt.Println("密钥对已从数据库删除")
	return nil
}
