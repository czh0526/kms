package main

import (
	"fmt"
	"log"

	"github.com/czh0526/kms/config"
	"github.com/czh0526/kms/store"
)

func main() {
	configPath := "etc/config.yaml"
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	fmt.Printf("Loaded config: %+v\n", cfg)

	// 构建 store 实例
	keyStore, err := store.NewKeyStore(cfg)
	if err != nil {
		log.Fatalf("Failed to create key store: %v", err)
	}
}
