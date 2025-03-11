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

var Cfg = Configuration{}

/*
	General rule for reading order of configuration values:
	1. Command line.
	2. Config file thats name is declared on the command line.
	3. Environment vars - implemented
	4. Local config file (if exists) - implemented
	5. Global config file (if exists)
	6. Default values - implemented
*/

func (c *Configuration) loadConfig(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(data, c)
	if err != nil {
		return err
	}

	if serverAddress := os.Getenv("SERVER_ADDRESS"); serverAddress != "" {
		log.Printf("Using environment variable for SERVER_ADDRESS: %s\n", serverAddress)
		c.Server.Address = serverAddress
	}

	if masterKey := os.Getenv("MASTER_KEY"); masterKey != "" {
		log.Printf("Using environment variable for MASTER_KEY: %s\n", masterKey)
		c.MasterKey = masterKey
	}

	if databasePath := os.Getenv("DATABASE_PATH"); databasePath != "" {
		log.Printf("Using environment variable for DATABASE_PATH: %s\n", databasePath)
		c.Database.Path = databasePath
	}

	return nil
}

func init() {
	// Load configuration
	err := Cfg.loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
}
