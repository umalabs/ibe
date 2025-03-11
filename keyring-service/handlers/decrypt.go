package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/umalabs/ibe/keyring-service/keyring-service/auth"
	"github.com/umalabs/ibe/keyring-service/keyring-service/config"
	"github.com/umalabs/ibe/keyring-service/keyring-service/hkdf"
)

func DecryptKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate the request
	email, err := auth.AuthenticateRequest(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Read the ciphertext and identity AAD tag from the request body
	var request struct {
		ContentEncKeyCiphertext string `json:"contentEncKeyCiphertext"` // Base64 encoded
		IdentityAADTag          string `json:"identityAADTag"`          // Base64 encoded
		IdentityNonce           string `json:"identityNonce"`           // Base64 encoded
		IdentityIV              string `json:"identityIV"`              // Base64 encoded
	}

	err = json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Decode the inputs
	ciphertext, err := base64.StdEncoding.DecodeString(request.ContentEncKeyCiphertext)
	if err != nil {
		http.Error(w, "Invalid Ciphertext", http.StatusBadRequest)
		return
	}
	identityNonce, err := base64.StdEncoding.DecodeString(request.IdentityNonce)
	if err != nil {
		http.Error(w, "Invalid Identity Nonce", http.StatusBadRequest)
		return
	}
	iv, err := base64.StdEncoding.DecodeString(request.IdentityIV)
	if err != nil {
		http.Error(w, "Invalid Identity IV", http.StatusBadRequest)
		return
	}
	// For this prototype, we're not using IdentityAADTag

	// Load the Master Key from the config
	masterKeyBytes, err := base64.StdEncoding.DecodeString(config.Cfg.MasterKey)
	if err != nil {
		http.Error(w, "Invalid Master Key", http.StatusInternalServerError)
		return
	}

	// Derive Identity Encryption Key using HKDF (simplified)
	identityEncKey := hkdf.DeriveKey(masterKeyBytes, identityNonce)

	// Decrypt the Content Encryption Key using AES-256-GCM
	block, err := aes.NewCipher(identityEncKey)
	if err != nil {
		http.Error(w, "Error creating cipher", http.StatusInternalServerError)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "Error creating GCM", http.StatusInternalServerError)
		return
	}

	// The AAD should match what was used during encryption (identityNonce and email)
	aad := append(identityNonce, []byte(email)...)

	// Decrypt the ciphertext
	contentEncKey, err := gcm.Open(nil, iv, ciphertext, aad)
	if err != nil {
		http.Error(w, "Decryption Failed", http.StatusBadRequest)
		return
	}

	// Send back the decrypted Content Encryption Key
	response := struct {
		ContentEncKey string `json:"contentEncKey"` // Base64 encoded
	}{
		ContentEncKey: base64.StdEncoding.EncodeToString(contentEncKey),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
