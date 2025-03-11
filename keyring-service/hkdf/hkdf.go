package hkdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

func DeriveKey(masterKey, salt []byte) []byte {
	// Simplified HKDF implementation
	// In production, use the standard crypto/hkdf package

	hashFunc := sha256.New
	prk := hkdfExtract(hashFunc, salt, masterKey)
	okm := hkdfExpand(hashFunc, prk, nil, 32) // Derive 32 bytes key
	return okm
}

func hkdfExtract(hashFunc func() hash.Hash, salt, inputKeyMaterial []byte) []byte {
	if salt == nil {
		salt = make([]byte, hashFunc().Size())
	}
	h := hmac.New(hashFunc, salt)
	h.Write(inputKeyMaterial)
	return h.Sum(nil)
}

func hkdfExpand(hashFunc func() hash.Hash, prk, info []byte, length int) []byte {
	n := (length + hashFunc().Size() - 1) / hashFunc().Size()
	t := make([]byte, 0, n*hashFunc().Size())
	var prev []byte
	for i := 0; i < n; i++ {
		h := hmac.New(hashFunc, prk)
		h.Write(prev)
		if info != nil {
			h.Write(info)
		}
		h.Write([]byte{byte(i + 1)})
		prev = h.Sum(nil)
		t = append(t, prev...)
	}
	return t[:length]
}
