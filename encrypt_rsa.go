/**
 * @Author: lidonglin
 * @Description:
 * @File:  encrypt_rsa.go
 * @Version: 1.0.0
 * @Date: 2023/10/31 16:01
 */

package tutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Public-key PEM forms for ResetRsaKeyType and parsers:
// PublicKeyPKIX = PKIX SubjectPublicKeyInfo; PublicKeyPKCS1 = PKCS#1 RSAPublicKey.
const (
	PublicKeyPKIX = iota
	PublicKeyPKCS1
)

// Private-key PEM forms: PrivateKeyPKCS1 = PKCS#1 RSAPrivateKey; PrivateKeyPKCS8 = PKCS#8 PrivateKeyInfo.
const (
	PrivateKeyPKCS1 = iota
	PrivateKeyPKCS8
)

var (
	rsaKeyTypeMutex sync.RWMutex

	rsaPublicKeyType  = PublicKeyPKCS1
	rsaPrivateKeyType = PrivateKeyPKCS1
)

// ResetRsaKeyType sets the global PEM parse modes for RSA public and private keys (thread-safe).
func ResetRsaKeyType(publicKeyType int, privateKeyType int) {
	rsaKeyTypeMutex.Lock()
	defer rsaKeyTypeMutex.Unlock()

	rsaPublicKeyType = publicKeyType
	rsaPrivateKeyType = privateKeyType
}

// decodeRSAPEM decodes the first PEM block from key or returns an error if none.
func decodeRSAPEM(key []byte) (*pem.Block, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("failed to decode PEM: invalid or empty PEM data")
	}

	return block, nil
}

// RSAKeyGenerator generates an RSA key pair of bits length via crypto/rand and writes private.pem and public.pem in the current directory.
// Wire formats follow the global types set by ResetRsaKeyType.
func RSAKeyGenerator(bits int) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	var X509PrivateKey []byte

	rsaKeyTypeMutex.RLock()

	publicKeyType, privateKeyType := rsaPublicKeyType, rsaPrivateKeyType

	rsaKeyTypeMutex.RUnlock()

	if privateKeyType == PrivateKeyPKCS1 {
		X509PrivateKey = x509.MarshalPKCS1PrivateKey(privateKey)
	} else {
		X509PrivateKey, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return err
		}
	}

	privateFile, err := os.Create("private.pem")
	if err != nil {
		return err
	}

	defer privateFile.Close()

	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}

	err = pem.Encode(privateFile, &privateBlock)
	if err != nil {
		return err
	}

	publicKey := privateKey.PublicKey

	var X509PublicKey []byte

	if publicKeyType == PublicKeyPKIX {
		X509PublicKey, err = x509.MarshalPKIXPublicKey(&publicKey)
		if err != nil {
			return err
		}
	} else {
		X509PublicKey = x509.MarshalPKCS1PublicKey(&publicKey)
	}

	publicFile, err := os.Create("public.pem")
	if err != nil {
		return err
	}

	defer publicFile.Close()

	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}

	err = pem.Encode(publicFile, &publicBlock)
	if err != nil {
		return err
	}

	return nil
}

// RsaEncrypt encrypts plainText with RSA PKCS1v15. key is PEM-encoded public key bytes; format from ResetRsaKeyType.
func RsaEncrypt(plainText, key []byte) ([]byte, error) {
	block, err := decodeRSAPEM(key)
	if err != nil {
		return nil, err
	}

	rsaKeyTypeMutex.RLock()

	publicKeyType := rsaPublicKeyType

	rsaKeyTypeMutex.RUnlock()

	var publicKey *rsa.PublicKey

	if publicKeyType == PublicKeyPKIX {
		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		var ok bool

		publicKey, ok = publicInterface.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not RSA: got %T", publicInterface)
		}
	} else {
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		return nil, err
	}

	return cipherText, nil
}

// RsaDecrypt decrypts ciphertext with RSA PKCS1v15. key is PEM-encoded private key bytes.
func RsaDecrypt(cipherText, key []byte) ([]byte, error) {
	block, err := decodeRSAPEM(key)
	if err != nil {
		return nil, err
	}

	rsaKeyTypeMutex.RLock()

	privateKeyType := rsaPrivateKeyType

	rsaKeyTypeMutex.RUnlock()

	var privateKey *rsa.PrivateKey

	if privateKeyType == PrivateKeyPKCS1 {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	} else {
		privateInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		var ok bool

		privateKey, ok = privateInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA: got %T", privateInterface)
		}
	}

	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// RsaSignature signs SHA-256(cipherText) with PKCS1v15 using the PEM private key in key.
func RsaSignature(cipherText, key []byte) ([]byte, error) {
	block, err := decodeRSAPEM(key)
	if err != nil {
		return nil, err
	}

	rsaKeyTypeMutex.RLock()

	privateKeyType := rsaPrivateKeyType

	rsaKeyTypeMutex.RUnlock()

	var privateKey *rsa.PrivateKey

	if privateKeyType == PrivateKeyPKCS1 {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	} else {
		privateInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		var ok bool

		privateKey, ok = privateInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA: got %T", privateInterface)
		}
	}

	hash := sha256.New()
	hash.Write(cipherText)

	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash.Sum(nil))

	return sign, err
}

// RsaSignatureVerify verifies PKCS1v15 signature sign over SHA-256(cipherText) with the PEM public key in key.
// Returns (true, nil) on success; otherwise false and a non-nil err describing the failure.
func RsaSignatureVerify(cipherText, sign, key []byte) (bool, error) {
	block, err := decodeRSAPEM(key)
	if err != nil {
		return false, err
	}

	rsaKeyTypeMutex.RLock()

	publicKeyType := rsaPublicKeyType

	rsaKeyTypeMutex.RUnlock()

	var publicKey *rsa.PublicKey

	if publicKeyType == PublicKeyPKIX {
		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return false, err
		}

		var ok bool

		publicKey, ok = publicInterface.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("public key is not RSA: got %T", publicInterface)
		}
	} else {
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return false, err
		}
	}

	hash := sha256.New()
	hash.Write(cipherText)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash.Sum(nil), sign)
	if err != nil {
		return false, err
	}

	return true, nil
}
