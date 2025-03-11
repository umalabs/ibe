package main

import (
	"log"
	"net/http"

	"github.com/umalabs/ibe/keyring-service/keyring-service/config"
	"github.com/umalabs/ibe/keyring-service/keyring-service/database"
	"github.com/umalabs/ibe/keyring-service/keyring-service/handlers"
)

func main() {
	// Initialize database (if needed)
	database.InitDB(config.Cfg.Database.Path)

	// Start HTTP server
	mux := http.NewServeMux()

	// Register handlers
	mux.HandleFunc("/encryptKey", handlers.EncryptKeyHandler)
	mux.HandleFunc("/decryptKey", handlers.DecryptKeyHandler)

	log.Printf("Starting server on %s...", config.Cfg.Server.Address)
	err := http.ListenAndServe(config.Cfg.Server.Address, mux)
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
