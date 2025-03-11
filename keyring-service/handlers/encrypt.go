package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"github.com/umalabs/ibe/keyring-service/keyring-service/config"
	"github.com/umalabs/ibe/keyring-service/keyring-service/hkdf"
)

var email string = "izboran@gmail.com"

func EncryptKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the content encryption key from the request body
	var request struct {
		ContentEncKey string `json:"contentEncKey"` // Base64 encoded
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Decode the content encryption key
	contentEncKey, err := base64.StdEncoding.DecodeString(request.ContentEncKey)
	if err != nil {
		http.Error(w, "Invalid Content Encryption Key", http.StatusBadRequest)
		return
	}

	// Load the Master Key from the config
	masterKeyBytes, err := base64.StdEncoding.DecodeString(config.Config.MasterKey)
	if err != nil {
		http.Error(w, "Invalid Master Key", http.StatusInternalServerError)
		return
	}

	// Generate Identity Nonce (random)
	identityNonce := make([]byte, 16) // 16 bytes nonce
	_, err = rand.Read(identityNonce)
	if err != nil {
		http.Error(w, "Error generating nonce", http.StatusInternalServerError)
		return
	}

	// Derive Identity Encryption Key using HKDF (simplified for this prototype)
	identityEncKey := hkdf.DeriveKey(masterKeyBytes, identityNonce)

	// Encrypt the Content Encryption Key using AES-256-GCM
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

	// Generate a random IV
	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		http.Error(w, "Error generating IV", http.StatusInternalServerError)
		return
	}

	// For AAD, we'll use the identityNonce and email (this is a simplification)
	aad := append(identityNonce, []byte(email)...)

	// Encrypt the content encryption key
	ciphertext := gcm.Seal(nil, iv, contentEncKey, aad)

	// Prepare the response
	response := struct {
		ContentEncKeyCiphertext string `json:"contentEncKeyCiphertext"` // Base64 encoded
		IdentityAADTag          string `json:"identityAADTag"`          // Base64 encoded GCM tag
		IdentityNonce           string `json:"identityNonce"`           // Base64 encoded
		IdentityIV              string `json:"identityIV"`              // Base64 encoded
	}{
		ContentEncKeyCiphertext: base64.StdEncoding.EncodeToString(ciphertext),
		IdentityAADTag:          base64.StdEncoding.EncodeToString(aad),
		IdentityNonce:           base64.StdEncoding.EncodeToString(identityNonce),
		IdentityIV:              base64.StdEncoding.EncodeToString(iv),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
