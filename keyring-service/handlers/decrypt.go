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

	// Read the ciphertext and identity AAD tag from the request body
	var request struct {
		ContentEncKeyCiphertext string `json:"contentEncKeyCiphertext"` // Base64 encoded
		IdentityAADTag          string `json:"identityAADTag"`          // Base64 encoded
		IdentityNonce           string `json:"identityNonce"`           // Base64 encoded
		IdentityIV              string `json:"identityIV"`              // Base64 encoded
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Bad Request: Invalid request body", http.StatusBadRequest)
		return
	}

	// Decode the inputs
	ciphertext, err := base64.StdEncoding.DecodeString(request.ContentEncKeyCiphertext)
	if err != nil {
		http.Error(w, "Bad Request: Invalid Ciphertext", http.StatusBadRequest)
		return
	}
	identityNonce, err := base64.StdEncoding.DecodeString(request.IdentityNonce)
	if err != nil {
		http.Error(w, "Bad Request: Invalid Identity Nonce", http.StatusBadRequest)
		return
	}
	iv, err := base64.StdEncoding.DecodeString(request.IdentityIV)
	if err != nil {
		http.Error(w, "Bad Request: Invalid Identity IV", http.StatusBadRequest)
		return
	}
	receivedAAD, err := base64.StdEncoding.DecodeString(request.IdentityAADTag)
	if err != nil {
		http.Error(w, "Bad Request: Invalid Identity AAD Tag", http.StatusBadRequest)
		return
	}

	// Authenticate the request
	email, err := auth.AuthenticateRequest(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Check if the user is the owner
	if email != config.Cfg.Owner {
		http.Error(w, "Unauthorized: not owner", http.StatusUnauthorized)
		return
	}

	// Load the Master Key from the config
	masterKeyBytes, err := base64.StdEncoding.DecodeString(config.Cfg.MasterKey)
	if err != nil {
		http.Error(w, "Internal Server Error: Invalid Master Key", http.StatusInternalServerError)
		return
	}

	// Derive Identity Encryption Key using HKDF (simplified)
	identityEncKey := hkdf.DeriveKey(masterKeyBytes, identityNonce)

	// Decrypt the Content Encryption Key using AES-256-GCM
	block, err := aes.NewCipher(identityEncKey)
	if err != nil {
		http.Error(w, "Internal Server Error: Error creating cipher", http.StatusInternalServerError)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "Internal Server Error: Error creating GCM", http.StatusInternalServerError)
		return
	}

	// The AAD should match what was used during encryption (identityNonce and email)
	aad := append(identityNonce, []byte(email)...)

	// Verify the AAD
	if len(aad) != len(receivedAAD) || !compareByteSlices(aad, receivedAAD) {
		http.Error(w, "Bad Request: AAD verification failed", http.StatusBadRequest)
		return
	}

	// Decrypt the ciphertext
	contentEncKey, err := gcm.Open(nil, iv, ciphertext, aad)
	if err != nil {
		http.Error(w, "Bad Request: Decryption Failed", http.StatusBadRequest)
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

func compareByteSlices(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
