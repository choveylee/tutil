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

// PublicKeyPKIX and PublicKeyPKCS1 select RSA public-key PEM encodings.
const (
	PublicKeyPKIX  = iota // PKIX SubjectPublicKeyInfo (SPKI)
	PublicKeyPKCS1        // ANSI PKCS #1 RSAPublicKey
)

// PrivateKeyPKCS1 and PrivateKeyPKCS8 select RSA private-key PEM encodings.
const (
	PrivateKeyPKCS1 = iota // ANSI PKCS #1 RSAPrivateKey
	PrivateKeyPKCS8        // PKCS #8 PrivateKeyInfo
)

var (
	rsaKeyTypeMutex sync.RWMutex

	rsaPublicKeyType  = PublicKeyPKCS1
	rsaPrivateKeyType = PrivateKeyPKCS1
)

// ResetRsaKeyType configures the default PEM encodings used when
// RSAKeyGenerator and RSAKeyGeneratorTo write key files.
// It is safe for concurrent use. Invalid selectors return an error and leave
// the current configuration unchanged.
func ResetRsaKeyType(publicKeyType int, privateKeyType int) error {
	if publicKeyType != PublicKeyPKCS1 && publicKeyType != PublicKeyPKIX {
		return fmt.Errorf("rsa: unsupported public key encoding selector %d", publicKeyType)
	}

	if privateKeyType != PrivateKeyPKCS1 && privateKeyType != PrivateKeyPKCS8 {
		return fmt.Errorf("rsa: unsupported private key encoding selector %d", privateKeyType)
	}

	rsaKeyTypeMutex.Lock()
	defer rsaKeyTypeMutex.Unlock()

	rsaPublicKeyType = publicKeyType
	rsaPrivateKeyType = privateKeyType

	return nil
}

// decodeRSAPEM decodes and returns the first PEM block in key, or an error if
// the PEM data is empty or malformed.
func decodeRSAPEM(key []byte) (*pem.Block, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("rsa: PEM data is empty or malformed")
	}

	return block, nil
}

func parsePKIXRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	publicInterface, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	publicKey, ok := publicInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("rsa: parsed public key has type %T; expected *rsa.PublicKey", publicInterface)
	}

	return publicKey, nil
}

func parsePKCS8RSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	privateInterface, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}

	privateKey, ok := privateInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("rsa: parsed private key has type %T; expected *rsa.PrivateKey", privateInterface)
	}

	return privateKey, nil
}

func parseRSAPublicKey(block *pem.Block) (*rsa.PublicKey, error) {
	switch block.Type {
	case "PUBLIC KEY":
		return parsePKIXRSAPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}

	publicKey, err := parsePKIXRSAPublicKey(block.Bytes)
	if err == nil {
		return publicKey, nil
	}

	publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return publicKey, nil
	}

	return nil, fmt.Errorf("rsa: unsupported PEM block type %q for an RSA public key", block.Type)
}

func parseRSAPrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	switch block.Type {
	case "PRIVATE KEY":
		return parsePKCS8RSAPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, nil
	}

	privateKey, err = parsePKCS8RSAPrivateKey(block.Bytes)
	if err == nil {
		return privateKey, nil
	}

	return nil, fmt.Errorf("rsa: unsupported PEM block type %q for an RSA private key", block.Type)
}

// RSAKeyGenerator generates an RSA key pair and writes private.pem and public.pem to the current working directory.
func RSAKeyGenerator(bits int) error {
	return RSAKeyGeneratorTo(".", bits)
}

// RSAKeyGeneratorTo generates an RSA key pair and writes private.pem and public.pem into dir.
// bits must be at least 1024. For new deployments, 2048 bits or larger is recommended.
// The private key file is written with mode 0o600.
func RSAKeyGeneratorTo(dir string, bits int) error {
	if bits < 1024 {
		return fmt.Errorf("rsa: RSA key size %d bits is too small; minimum is 1024 bits", bits)
	}

	rsaKeyTypeMutex.RLock()

	publicKeyType, privateKeyType := rsaPublicKeyType, rsaPrivateKeyType

	rsaKeyTypeMutex.RUnlock()

	if publicKeyType != PublicKeyPKCS1 && publicKeyType != PublicKeyPKIX {
		return fmt.Errorf("rsa: unsupported public key encoding selector %d", publicKeyType)
	}

	if privateKeyType != PrivateKeyPKCS1 && privateKeyType != PrivateKeyPKCS8 {
		return fmt.Errorf("rsa: unsupported private key encoding selector %d", privateKeyType)
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

// RsaEncrypt encrypts plaintext using RSAES-OAEP with SHA-256.
// key must contain a PEM-encoded RSA public key.
func RsaEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := decodeRSAPEM(key)
	if err != nil {
		return nil, err
	}

	publicKey, err := parseRSAPublicKey(block)
	if err != nil {
		return nil, err
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// RsaDecrypt decrypts ciphertext using RSAES-OAEP with SHA-256.
// key must contain a PEM-encoded RSA private key.
func RsaDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := decodeRSAPEM(key)
	if err != nil {
		return nil, err
	}

	privateKey, err := parseRSAPrivateKey(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// RsaSignature returns an RSASSA-PKCS1-v1_5 signature over the SHA-256 digest of message.
// key must contain a PEM-encoded RSA private key.
func RsaSignature(message, key []byte) ([]byte, error) {
	block, err := decodeRSAPEM(key)
	if err != nil {
		return nil, err
	}

	privateKey, err := parseRSAPrivateKey(block)
	if err != nil {
		return nil, err
	}

	h := sha256.Sum256(message)

	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h[:])
}

// RsaSignatureVerify reports whether sign is a valid RSASSA-PKCS1-v1_5 signature
// over the SHA-256 digest of message for the PEM-encoded public key in key.
func RsaSignatureVerify(message, sign, key []byte) (bool, error) {
	block, err := decodeRSAPEM(key)
	if err != nil {
		return false, err
	}

	publicKey, err := parseRSAPublicKey(block)
	if err != nil {
		return false, err
	}

	h := sha256.Sum256(message)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h[:], sign)
	if err != nil {
		return false, err
	}

	return true, nil
}
