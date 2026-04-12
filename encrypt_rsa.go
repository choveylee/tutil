/**
 * @Author: lidonglin
 * @Description: RSA PEM parse/encrypt/decrypt/sign/verify and key pair writer (RSAKeyGeneratorTo).
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
	"path/filepath"
	"sync"
)

// PublicKeyPKIX and PublicKeyPKCS1 are public-key PEM layout values for ResetRsaKeyType and the RSA PEM parsers.
const (
	PublicKeyPKIX = iota // PKIX SubjectPublicKeyInfo (SPKI)
	PublicKeyPKCS1       // PKCS#1 RSAPublicKey
)

// PrivateKeyPKCS1 and PrivateKeyPKCS8 are private-key PEM layout values for ResetRsaKeyType and the RSA PEM parsers.
const (
	PrivateKeyPKCS1 = iota // PKCS#1 RSAPrivateKey
	PrivateKeyPKCS8        // PKCS#8 PrivateKeyInfo
)

var (
	rsaKeyTypeMutex sync.RWMutex

	rsaPublicKeyType  = PublicKeyPKCS1
	rsaPrivateKeyType = PrivateKeyPKCS1
)

// ResetRsaKeyType sets the global PEM parsing modes for RSA public and private keys. It is safe for concurrent use.
func ResetRsaKeyType(publicKeyType int, privateKeyType int) {
	rsaKeyTypeMutex.Lock()
	defer rsaKeyTypeMutex.Unlock()

	rsaPublicKeyType = publicKeyType
	rsaPrivateKeyType = privateKeyType
}

// decodeRSAPEM decodes and returns the first PEM block in key, or an error if none is found.
func decodeRSAPEM(key []byte) (*pem.Block, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("rsa: PEM data is empty or not valid PEM")
	}

	return block, nil
}

// RSAKeyGenerator generates an RSA key pair and writes private.pem and public.pem in the current working directory.
func RSAKeyGenerator(bits int) error {
	return RSAKeyGeneratorTo(".", bits)
}

// RSAKeyGeneratorTo generates an RSA key pair and writes private.pem and public.pem into dir. bits must be at least 1024; the private key file uses mode 0600 and PEM types match common OpenSSL conventions.
func RSAKeyGeneratorTo(dir string, bits int) error {
	if bits < 1024 {
		return fmt.Errorf("rsa: key size %d bits is below the minimum of 1024", bits)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	var privateDER []byte

	rsaKeyTypeMutex.RLock()

	publicKeyType, privateKeyType := rsaPublicKeyType, rsaPrivateKeyType

	rsaKeyTypeMutex.RUnlock()

	if privateKeyType == PrivateKeyPKCS1 {
		privateDER = x509.MarshalPKCS1PrivateKey(privateKey)
	} else {
		privateDER, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return err
		}
	}

	privPEMType := "RSA PRIVATE KEY"
	if privateKeyType == PrivateKeyPKCS8 {
		privPEMType = "PRIVATE KEY"
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	privatePath := filepath.Join(dir, "private.pem")
	privateFile, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	defer privateFile.Close()

	privateBlock := pem.Block{Type: privPEMType, Bytes: privateDER}

	if err := pem.Encode(privateFile, &privateBlock); err != nil {
		return err
	}

	publicKey := privateKey.PublicKey

	var pubDER []byte

	if publicKeyType == PublicKeyPKIX {
		pubDER, err = x509.MarshalPKIXPublicKey(&publicKey)
		if err != nil {
			return err
		}
	} else {
		pubDER = x509.MarshalPKCS1PublicKey(&publicKey)
	}

	pubPEMType := "RSA PUBLIC KEY"
	if publicKeyType == PublicKeyPKIX {
		pubPEMType = "PUBLIC KEY"
	}

	publicPath := filepath.Join(dir, "public.pem")
	publicFile, err := os.OpenFile(publicPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}

	defer publicFile.Close()

	publicBlock := pem.Block{Type: pubPEMType, Bytes: pubDER}

	return pem.Encode(publicFile, &publicBlock)
}

// RsaEncrypt encrypts plaintext with RSA PKCS1v15. key must hold a PEM-encoded public key in the format selected by ResetRsaKeyType.
func RsaEncrypt(plaintext, key []byte) ([]byte, error) {
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
			return nil, fmt.Errorf("rsa: public key has type %T; *rsa.PublicKey required", publicInterface)
		}
	} else {
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// RsaDecrypt decrypts ciphertext with RSA PKCS1v15. key must hold a PEM-encoded private key in the format selected by ResetRsaKeyType.
func RsaDecrypt(ciphertext, key []byte) ([]byte, error) {
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
			return nil, fmt.Errorf("rsa: private key has type %T; *rsa.PrivateKey required", privateInterface)
		}
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// RsaSignature returns the RSA PKCS1v15 signature of SHA-256(message) using the PEM-encoded private key in key.
func RsaSignature(message, key []byte) ([]byte, error) {
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
			return nil, fmt.Errorf("rsa: private key has type %T; *rsa.PrivateKey required", privateInterface)
		}
	}

	h := sha256.Sum256(message)

	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h[:])
}

// RsaSignatureVerify reports whether sign is a valid RSA PKCS1v15 signature of SHA-256(message) for the PEM-encoded public key in key.
func RsaSignatureVerify(message, sign, key []byte) (bool, error) {
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
			return false, fmt.Errorf("rsa: public key has type %T; *rsa.PublicKey required", publicInterface)
		}
	} else {
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return false, err
		}
	}

	h := sha256.Sum256(message)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h[:], sign)
	if err != nil {
		return false, err
	}

	return true, nil
}
