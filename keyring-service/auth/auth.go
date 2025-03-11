package auth

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// GoogleJWKsURL is the URL to retrieve Google's JSON Web Key Set (JWKS).
const GoogleJWKsURL = "https://www.googleapis.com/oauth2/v3/certs"

// jwkCache stores the Google public keys.
var (
	jwkCache   map[string]*rsa.PublicKey
	cacheMutex sync.RWMutex
	lastUpdate time.Time
)

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// fetchGooglePublicKeys fetches and caches Google's public keys.
func fetchGooglePublicKeys() error {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	// Check if the cache is valid (e.g., updated within the last 24 hours).
	if time.Since(lastUpdate) < 24*time.Hour && jwkCache != nil {
		return nil // Cache is valid.
	}

	resp, err := http.Get(GoogleJWKsURL)
	if err != nil {
		return fmt.Errorf("failed to fetch Google's public keys: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to unmarshal JWKS: %v", err)
	}

	newCache := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty == "RSA" {
			key, err := parseRSAPublicKeyFromJWK(&jwk)
			if err != nil {
				return fmt.Errorf("failed to parse RSA public key: %v", err)
			}
			newCache[jwk.Kid] = key
		}
	}

	jwkCache = newCache
	lastUpdate = time.Now()

	return nil
}

// parseRSAPublicKeyFromJWK parses an RSA public key from JWK.
func parseRSAPublicKeyFromJWK(jwk *JWK) (*rsa.PublicKey, error) {
	n, err := jwt.DecodeSegment(jwk.N)
	if err != nil {
		return nil, err
	}
	e, err := jwt.DecodeSegment(jwk.E)
	if err != nil {
		return nil, err
	}

	// Convert the base64-decoded values to big.Int
	nInt := new(big.Int).SetBytes(n)
	eInt := new(big.Int).SetBytes(e)

	// Ensure eInt is positive, it is usually 65537 which is a small number
	if eInt.Cmp(big.NewInt(0)) <= 0 {
		return nil, fmt.Errorf("invalid public exponent (e)")
	}

	// Convert the big.Int public exponent to an integer
	// as it is safe to assume it will not overflow int
	eParsed := int(eInt.Int64())

	// Create the RSA public key
	publicKey := &rsa.PublicKey{
		N: nInt,
		E: eParsed,
	}
	return publicKey, nil
}

func AuthenticateRequest(r *http.Request) (string, error) {
	// Extract the Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid Authorization header format")
	}

	tokenString := parts[1]

	// Fetch and cache Google's public keys.
	if err := fetchGooglePublicKeys(); err != nil {
		return "", fmt.Errorf("failed to fetch Google's public keys: %v", err)
	}

	// Parse and validate the JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method.
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get the key ID from the header.
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		cacheMutex.RLock()
		defer cacheMutex.RUnlock()

		// Look up the key in the cache.
		key, ok := jwkCache[kid]
		if !ok {
			return nil, fmt.Errorf("key not found for kid: %s", kid)
		}

		return key, nil
	})

	if err != nil {
		return "", fmt.Errorf("invalid token: %v", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	// Retrieve the email claim
	email, ok := claims["email"].(string)
	if !ok {
		return "", fmt.Errorf("email claim not found")
	}

	// Optionally, verify the 'aud' and 'azp' claims if needed

	return email, nil
}
