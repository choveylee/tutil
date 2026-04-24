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

// PublicKeyPKIX and PublicKeyPKCS1 select the PEM encoding format for RSA public keys in ResetRsaKeyType and related parsers.
const (
	PublicKeyPKIX  = iota // PKIX SubjectPublicKeyInfo (SPKI)
	PublicKeyPKCS1        // ANSI PKCS #1 RSAPublicKey
)

// PrivateKeyPKCS1 and PrivateKeyPKCS8 select the PEM encoding format for RSA private keys in ResetRsaKeyType and related parsers.
const (
	PrivateKeyPKCS1 = iota // ANSI PKCS #1 RSAPrivateKey
	PrivateKeyPKCS8        // PKCS #8 PrivateKeyInfo
)

var (
	rsaKeyTypeMutex sync.RWMutex

	rsaPublicKeyType  = PublicKeyPKCS1
	rsaPrivateKeyType = PrivateKeyPKCS1
)

// ResetRsaKeyType configures the PEM decoding formats used for RSA public and private keys throughout this package.
// It is safe for concurrent use. Invalid key types return an error and leave the current configuration unchanged.
func ResetRsaKeyType(publicKeyType int, privateKeyType int) error {
	if publicKeyType != PublicKeyPKCS1 && publicKeyType != PublicKeyPKIX {
		return fmt.Errorf("rsa: unsupported public key type %d", publicKeyType)
	}

	if privateKeyType != PrivateKeyPKCS1 && privateKeyType != PrivateKeyPKCS8 {
		return fmt.Errorf("rsa: unsupported private key type %d", privateKeyType)
	}

	rsaKeyTypeMutex.Lock()
	defer rsaKeyTypeMutex.Unlock()

	rsaPublicKeyType = publicKeyType
	rsaPrivateKeyType = privateKeyType

	return nil
}

// decodeRSAPEM decodes and returns the first PEM block in key, or an error if decoding fails.
func decodeRSAPEM(key []byte) (*pem.Block, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("rsa: PEM data is empty or not valid PEM")
	}

	return block, nil
}

// RSAKeyGenerator generates an RSA key pair and writes private.pem and public.pem to the current working directory.
func RSAKeyGenerator(bits int) error {
	return RSAKeyGeneratorTo(".", bits)
}

// RSAKeyGeneratorTo generates an RSA key pair and writes private.pem and public.pem into dir.
// bits must be at least 1024. The private key file is created with mode 0o600; PEM types follow common OpenSSL conventions.
func RSAKeyGeneratorTo(dir string, bits int) error {
	if bits < 1024 {
		return fmt.Errorf("rsa: key size %d bits is below the minimum of 1024", bits)
	}

	rsaKeyTypeMutex.RLock()

	publicKeyType, privateKeyType := rsaPublicKeyType, rsaPrivateKeyType

	rsaKeyTypeMutex.RUnlock()

	if publicKeyType != PublicKeyPKCS1 && publicKeyType != PublicKeyPKIX {
		return fmt.Errorf("rsa: unsupported public key type %d", publicKeyType)
	}

	if privateKeyType != PrivateKeyPKCS1 && privateKeyType != PrivateKeyPKCS8 {
		return fmt.Errorf("rsa: unsupported private key type %d", privateKeyType)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	var privateDER []byte

	switch privateKeyType {
	case PrivateKeyPKCS1:
		privateDER = x509.MarshalPKCS1PrivateKey(privateKey)
	case PrivateKeyPKCS8:
		privateDER, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return err
		}
	}

	privatePemType := "RSA PRIVATE KEY"
	if privateKeyType == PrivateKeyPKCS8 {
		privatePemType = "PRIVATE KEY"
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

	if err := privateFile.Chmod(0o600); err != nil {
		return err
	}

	privateBlock := pem.Block{Type: privatePemType, Bytes: privateDER}

	if err := pem.Encode(privateFile, &privateBlock); err != nil {
		return err
	}

	publicKey := privateKey.PublicKey

	var pubDER []byte

	switch publicKeyType {
	case PublicKeyPKIX:
		pubDER, err = x509.MarshalPKIXPublicKey(&publicKey)
		if err != nil {
			return err
		}
	case PublicKeyPKCS1:
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

// RsaEncrypt encrypts plaintext using RSA encryption with PKCS #1 v1.5 padding.
// key must contain a PEM-encoded public key in the format configured by ResetRsaKeyType.
func RsaEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := decodeRSAPEM(key)
	if err != nil {
		return nil, err
	}

	rsaKeyTypeMutex.RLock()

	publicKeyType := rsaPublicKeyType

	rsaKeyTypeMutex.RUnlock()

	var publicKey *rsa.PublicKey

	switch publicKeyType {
	case PublicKeyPKIX:
		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		var ok bool

		publicKey, ok = publicInterface.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("rsa: public key has type %T; *rsa.PublicKey required", publicInterface)
		}
	case PublicKeyPKCS1:
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	default:
		if publicKeyType != PublicKeyPKCS1 && publicKeyType != PublicKeyPKIX {
			return nil, fmt.Errorf("rsa: unsupported public key type %d", publicKeyType)
		}
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// RsaDecrypt decrypts ciphertext using RSA decryption with PKCS #1 v1.5 padding.
// key must contain a PEM-encoded private key in the format configured by ResetRsaKeyType.
func RsaDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := decodeRSAPEM(key)
	if err != nil {
		return nil, err
	}

	rsaKeyTypeMutex.RLock()

	privateKeyType := rsaPrivateKeyType

	rsaKeyTypeMutex.RUnlock()

	var privateKey *rsa.PrivateKey

	switch privateKeyType {
	case PrivateKeyPKCS1:
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	case PrivateKeyPKCS8:
		privateInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		var ok bool

		privateKey, ok = privateInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("rsa: private key has type %T; *rsa.PrivateKey required", privateInterface)
		}
	default:
		if privateKeyType != PrivateKeyPKCS1 && privateKeyType != PrivateKeyPKCS8 {
			return nil, fmt.Errorf("rsa: unsupported private key type %d", privateKeyType)
		}
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// RsaSignature returns a PKCS #1 v1.5 signature over the SHA-256 hash of message using the PEM-encoded private key in key.
func RsaSignature(message, key []byte) ([]byte, error) {
	block, err := decodeRSAPEM(key)
	if err != nil {
		return nil, err
	}

	rsaKeyTypeMutex.RLock()

	privateKeyType := rsaPrivateKeyType

	rsaKeyTypeMutex.RUnlock()

	var privateKey *rsa.PrivateKey

	switch privateKeyType {
	case PrivateKeyPKCS1:
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	case PrivateKeyPKCS8:
		privateInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		var ok bool

		privateKey, ok = privateInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("rsa: private key has type %T; *rsa.PrivateKey required", privateInterface)
		}
	default:
		if privateKeyType != PrivateKeyPKCS1 && privateKeyType != PrivateKeyPKCS8 {
			return nil, fmt.Errorf("rsa: unsupported private key type %d", privateKeyType)
		}
	}

	h := sha256.Sum256(message)

	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h[:])
}

// RsaSignatureVerify reports whether sign is a valid PKCS #1 v1.5 signature over the SHA-256 hash of message
// for the PEM-encoded public key in key.
func RsaSignatureVerify(message, sign, key []byte) (bool, error) {
	block, err := decodeRSAPEM(key)
	if err != nil {
		return false, err
	}

	rsaKeyTypeMutex.RLock()

	publicKeyType := rsaPublicKeyType

	rsaKeyTypeMutex.RUnlock()

	var publicKey *rsa.PublicKey

	switch publicKeyType {
	case PublicKeyPKIX:
		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return false, err
		}

		var ok bool

		publicKey, ok = publicInterface.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("rsa: public key has type %T; *rsa.PublicKey required", publicInterface)
		}
	case PublicKeyPKCS1:
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return false, err
		}
	default:
		if publicKeyType != PublicKeyPKCS1 && publicKeyType != PublicKeyPKIX {
			return false, fmt.Errorf("rsa: unsupported public key type %d", publicKeyType)
		}
	}

	h := sha256.Sum256(message)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h[:], sign)
	if err != nil {
		return false, err
	}

	return true, nil
}
