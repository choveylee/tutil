/**
 * @Author: lidonglin
 * @Description: SM2 encrypt/decrypt and keygen via tjfoc/gmsm (C1C3C2).
 * @File:  encrypt_sm2.go
 * @Version: 1.0.0
 * @Date: 2024/8/24 13:18:31
 */

package tutil

import (
	"crypto/rand"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

// Sm2Decrypt decrypts SM2 ciphertext in C1C3C2 layout using hexPrivateKey as a hex-encoded private key.
func Sm2Decrypt(ciphertext []byte, hexPrivateKey string) ([]byte, error) {
	privateKey, err := x509.ReadPrivateKeyFromHex(hexPrivateKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := sm2.Decrypt(privateKey, ciphertext, sm2.C1C3C2)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Sm2Encrypt encrypts plaintext with SM2 using hexPublicKey as a hex-encoded public key; ciphertext uses C1C3C2 layout.
func Sm2Encrypt(plaintext []byte, hexPublicKey string) ([]byte, error) {
	publicKey, err := x509.ReadPublicKeyFromHex(hexPublicKey)
	if err != nil {
		return nil, err
	}

	ciphertext, err := sm2.Encrypt(publicKey, plaintext, rand.Reader, sm2.C1C3C2)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// GenSm2KeyPair generates an SM2 key pair from crypto/rand and returns hex-encoded private and public keys.
func GenSm2KeyPair() (string, string, error) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	hexPrivateKey := x509.WritePrivateKeyToHex(privateKey)
	hexPublicKey := x509.WritePublicKeyToHex(&privateKey.PublicKey)

	return hexPrivateKey, hexPublicKey, nil
}
