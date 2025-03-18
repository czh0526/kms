package store

import (
	"fmt"
	"sync"

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
func NewDBStore(dsn string) *DBStore {
	return &DBStore{dsn: dsn}
}

// initDB 初始化数据库连接
func (s *DBStore) initDB() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db != nil {
		return nil
	}

	db, err := gorm.Open(mysql.Open(s.dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	s.db = db
	return nil
}

// getDB 获取数据库连接
func (s *DBStore) getDB() (*gorm.DB, error) {
	if s.db == nil {
		if err := s.initDB(); err != nil {
			return nil, err
		}
	}
	return s.db, nil
}

// Save 保存密钥对到数据库
func (s *DBStore) Save(keyPair *keypair.KeyPair) error {
	db, err := s.getDB()
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
	db, err := s.getDB()
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
	db, err := s.getDB()
	if err != nil {
		return err
	}

	if err := db.Delete(&keypair.KeyPair{}, "address = ?", address).Error; err != nil {
		return err
	}

	fmt.Println("密钥对已从数据库删除")
	return nil
}
