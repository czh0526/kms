package main

import (
	"fmt"
	"log"
	"time"

	"github.com/czh0526/kms/config"
	kms_ecdsa "github.com/czh0526/kms/crypto/ecdsa"
	"github.com/czh0526/kms/store"
	"github.com/czh0526/kms/store/keypair"
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

	fmt.Printf("Created key store: %+v\n", keyStore)

	addressList := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		ecPrivateKey, err := kms_ecdsa.GenerateECDSAKey()
		if err != nil {
			log.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		keyPair, err := keypair.NewKeyPair(ecPrivateKey)
		if err != nil {
			log.Fatalf("Failed to create key pair: %v", err)
		}

		err = keyStore.Save(keyPair)
		if err != nil {
			log.Fatalf("Failed to save key pair: %v", err)
		}
		addressList = append(addressList, keyPair.Address)

		time.Sleep(1 * time.Second)
	}

	for idx, address := range addressList {
		keyPair, err := keyStore.Load(address)
		if err != nil {
			log.Fatalf("Failed to load key pair: %v", err)
		}
		fmt.Printf("Loaded key pair: %d \n", idx)

		kmsKey, err := keyPair.LoadKmsKey()
		if err != nil {
			log.Fatalf("Failed to load KMS key: %v", err)
		}
		fmt.Printf("Parse key: %d \n", idx)

		msg := []byte("hello")
		signature, err := kmsKey.Sign(msg)
		if err != nil {
			log.Fatalf("Failed to sign data: %v", err)
		}
		fmt.Printf("use key sign data: %d \n", idx)

		ok, err := kmsKey.Verify(msg, signature)
		if err != nil {
			log.Fatalf("Failed to verify signature: %v", err)
		}
		if !ok {
			log.Fatal("Signature verification failed")
		}
		fmt.Printf("use key verify signature: %d \n", idx)
		fmt.Println()
	}
}
