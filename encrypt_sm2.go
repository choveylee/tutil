package tutil

import (
	"crypto/rand"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

// Sm2Decrypt decrypts ciphertext using SM2 with ciphertext components in C1C3C2 order.
// hexPrivateKey must be a hexadecimal encoding of the private key.
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

// Sm2Encrypt encrypts plaintext using SM2.
// hexPublicKey must be a hexadecimal encoding of the public key.
// The returned ciphertext uses C1C3C2 component order.
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

// GenSm2KeyPair generates a new SM2 key pair using crypto/rand and returns the
// private and public keys as hexadecimal strings.
func GenSm2KeyPair() (string, string, error) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	hexPrivateKey := x509.WritePrivateKeyToHex(privateKey)
	hexPublicKey := x509.WritePublicKeyToHex(&privateKey.PublicKey)

	return hexPrivateKey, hexPublicKey, nil
}
