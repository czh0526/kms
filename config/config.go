package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	StoreType string `yaml:"StoreType"`
	FileStore *struct {
		Path string `yaml:"Path"`
	} `yaml:"FileStore"`
	DbStore *struct {
		DbType string `yaml:"DbType"`
		DSN    string `yaml:"DSN"`
	} `yaml:"DbStore"`
}

func Load(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
