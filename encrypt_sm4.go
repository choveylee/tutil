package tutil

import (
	"crypto/cipher"
	"fmt"

	"github.com/tjfoc/gmsm/sm4"
)

// sm4CheckCbcIV reports an error unless iv is exactly one block long.
func sm4CheckCbcIV(iv []byte, blockSize int) error {
	if len(iv) != blockSize {
		return fmt.Errorf("sm4 cbc: invalid IV length %d; expected %d bytes", len(iv), blockSize)
	}

	return nil
}

// Sm4EcbEncryptPKCS7 encrypts plaintext using SM4 in ECB mode with PKCS #7
// padding. key must be 16 bytes. ECB mode is retained only for legacy
// interoperability.
func Sm4EcbEncryptPKCS7(plaintext, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = PKCS7Padding(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(plaintext))

	if err := ecbEncryptBlocks(block, ciphertext, plaintext); err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// Sm4EcbDecryptPKCS7 decrypts ciphertext produced by Sm4EcbEncryptPKCS7 using the same key.
func Sm4EcbDecryptPKCS7(ciphertext, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))

	if err := ecbDecryptBlocks(block, plaintext, ciphertext); err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	plaintext, err = PKCS7UnPadding(plaintext, blockSize)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Sm4EcbEncryptZero encrypts plaintext using SM4 in ECB mode after ZeroPadding.
// key must be 16 bytes.
func Sm4EcbEncryptZero(plaintext, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = ZeroPadding(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(plaintext))

	if err := ecbEncryptBlocks(block, ciphertext, plaintext); err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// Sm4EcbDecryptZero decrypts ciphertext produced by Sm4EcbEncryptZero and removes zero padding.
func Sm4EcbDecryptZero(ciphertext, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))

	if err := ecbDecryptBlocks(block, plaintext, ciphertext); err != nil {
		return nil, err
	}

	plaintext, err = ZeroUnPadding(plaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Sm4CbcEncryptPKCS7 encrypts plaintext using SM4-CBC with PKCS #7 padding.
// key and iv must each be 16 bytes.
func Sm4CbcEncryptPKCS7(plaintext, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if err := sm4CheckCbcIV(iv, blockSize); err != nil {
		return nil, err
	}

	paddingData := PKCS7Padding(plaintext, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(paddingData))

	blockMode.CryptBlocks(ciphertext, paddingData)

	return ciphertext, nil
}

// Sm4CbcDecryptPKCS7 decrypts ciphertext produced by Sm4CbcEncryptPKCS7.
// It writes plaintext into a new buffer and does not overwrite ciphertext.
func Sm4CbcDecryptPKCS7(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if err := sm4CheckCbcIV(iv, blockSize); err != nil {
		return nil, err
	}

	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("sm4 cbc: ciphertext length %d is not a multiple of block size %d", len(ciphertext), blockSize)
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)

	plainBuf := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(plainBuf, ciphertext)

	plaintext, err := PKCS7UnPadding(plainBuf, blockSize)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Sm4CbcEncryptZero encrypts plaintext using SM4-CBC after ZeroPadding.
// key and iv must each be 16 bytes.
func Sm4CbcEncryptZero(plaintext, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if err := sm4CheckCbcIV(iv, blockSize); err != nil {
		return nil, err
	}

	paddingData := ZeroPadding(plaintext, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(paddingData))

	blockMode.CryptBlocks(ciphertext, paddingData)

	return ciphertext, nil
}

// Sm4CbcDecryptZero decrypts ciphertext produced by Sm4CbcEncryptZero and
// removes zero padding. It writes plaintext into a new buffer and does not
// overwrite ciphertext.
func Sm4CbcDecryptZero(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if err := sm4CheckCbcIV(iv, blockSize); err != nil {
		return nil, err
	}

	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("sm4 cbc: ciphertext length %d is not a multiple of block size %d", len(ciphertext), blockSize)
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)

	plainBuf := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(plainBuf, ciphertext)

	plaintext, err := ZeroUnPadding(plainBuf)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
