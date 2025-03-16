package store

import (
	"fmt"

	"github.com/czh0526/kms/keypair"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// DBStore 实现 Store 接口
type DBStore struct {
	dsn string
}

// NewDBStore 创建一个新的 DBStore
func NewDBStore(dsn string) *DBStore {
	return &DBStore{dsn: dsn}
}

// Save 保存密钥对到数据库
func (s *DBStore) Save(keyPair *keypair.KeyPair) error {
	db, err := gorm.Open(mysql.Open(s.dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	// 自动迁移模式
	db.AutoMigrate(&keypair.KeyPair{})

	if err := db.Create(keyPair).Error; err != nil {
		return err
	}

	fmt.Println("密钥对已保存到数据库")
	return nil
}

// Load 从数据库加载密钥对
func (s *DBStore) Load(address string) (*keypair.KeyPair, error) {
	db, err := gorm.Open(mysql.Open(s.dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	var keyPair keypair.KeyPair
	if err := db.First(&keyPair, "address = ?", address).Error; err != nil {
		return nil, err
	}

	return &keyPair, nil
}

// Delete 从数据库删除密钥对
func (s *DBStore) Delete(address string) error {
	db, err := gorm.Open(mysql.Open(s.dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	if err := db.Delete(&keypair.KeyPair{}, "address = ?", address).Error; err != nil {
		return err
	}

	fmt.Println("密钥对已从数据库删除")
	return nil
}