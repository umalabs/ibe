package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

type Configuration struct {
	Server    ServerConfig   `yaml:"server"`
	MasterKey string         `yaml:"masterKey"`
	Database  DatabaseConfig `yaml:"database"`
}

type ServerConfig struct {
	Address string `yaml:"address"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

var Config Configuration

func loadConfig(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(data, &Config)
	if err != nil {
		return err
	}
	return nil
}

func init() {
	// Load configuration
	err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
}
