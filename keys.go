package wgconf

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateKeyPair creates a new WireGuard keypair using X25519. Returns
// base64-encoded private and public keys.
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
		nil
}

// GeneratePresharedKey creates a random 32-byte preshared key, returned as base64.
func GeneratePresharedKey() (string, error) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return "", fmt.Errorf("generate preshared key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(psk), nil
}

// DerivePublicKey derives the public key from a base64-encoded X25519 private key.
func DerivePublicKey(privateKeyB64 string) (string, error) {
	privBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	if len(privBytes) != 32 {
		return "", fmt.Errorf("invalid private key length: %d", len(privBytes))
	}

	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}
