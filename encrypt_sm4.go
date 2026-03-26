/**
 * @Author: lidonglin
 * @Description:
 * @File:  encrypt_sm4.go
 * @Version: 1.0.0
 * @Date: 2024/8/24 12:37:38
 */

package tutil

import (
	"crypto/cipher"
	"fmt"

	"github.com/tjfoc/gmsm/sm4"
)

// sm4CheckCBCIV ensures len(iv) equals blockSize (16 for SM4).
func sm4CheckCBCIV(iv []byte, blockSize int) error {
	if len(iv) != blockSize {
		return fmt.Errorf("sm4 cbc: iv length %d must equal block size %d", len(iv), blockSize)
	}

	return nil
}

// Sm4EcbEncryptPKCS7 encrypts with SM4-ECB and PKCS#7 padding. key must be 16 bytes.
// ECB is weak for general confidentiality; prefer for legacy interoperability only.
func Sm4EcbEncryptPKCS7(plainText, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plainText = PKCS7Padding(plainText, block.BlockSize())

	cipherText := make([]byte, len(plainText))

	if err := ecbEncryptBlocks(block, cipherText, plainText); err != nil {
		return nil, err
	}

	return cipherText, nil
}

// Sm4EcbDecryptPKCS7 decrypts output from Sm4EcbEncryptPKCS7.
func Sm4EcbDecryptPKCS7(cipherText, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(cipherText))

	if err := ecbDecryptBlocks(block, plainText, cipherText); err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	plainText, err = PKCS7UnPadding(plainText, blockSize)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Sm4EcbEncryptZero encrypts with SM4-ECB and zero padding.
func Sm4EcbEncryptZero(plainText, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plainText = ZeroPadding(plainText, block.BlockSize())

	cipherText := make([]byte, len(plainText))

	if err := ecbEncryptBlocks(block, cipherText, plainText); err != nil {
		return nil, err
	}

	return cipherText, nil
}

// Sm4EcbDecryptZero decrypts SM4-ECB ciphertext with zero-padding removal.
func Sm4EcbDecryptZero(cipherText, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(cipherText))

	if err := ecbDecryptBlocks(block, plainText, cipherText); err != nil {
		return nil, err
	}

	plainText, err = ZeroUnPadding(plainText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Sm4CbcEncryptPKCS7 encrypts with SM4-CBC and PKCS#7. key and iv must be 16 bytes (iv checked by sm4CheckCBCIV).
func Sm4CbcEncryptPKCS7(plainText, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if err := sm4CheckCBCIV(iv, blockSize); err != nil {
		return nil, err
	}

	paddingData := PKCS7Padding(plainText, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, iv)

	cipherText := make([]byte, len(paddingData))

	blockMode.CryptBlocks(cipherText, paddingData)

	return cipherText, nil
}

// Sm4CbcDecryptPKCS7 decrypts SM4-CBC + PKCS#7 without overwriting the caller's cipherText slice.
func Sm4CbcDecryptPKCS7(cipherText, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if err := sm4CheckCBCIV(iv, blockSize); err != nil {
		return nil, err
	}

	if len(cipherText)%blockSize != 0 {
		return nil, fmt.Errorf("sm4 cbc: ciphertext length %d is not a multiple of block size %d", len(cipherText), blockSize)
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)

	plainBuf := make([]byte, len(cipherText))
	blockMode.CryptBlocks(plainBuf, cipherText)

	plainText, err := PKCS7UnPadding(plainBuf, blockSize)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Sm4CbcEncryptZero encrypts with SM4-CBC and zero padding; 16-byte key and iv.
func Sm4CbcEncryptZero(plainText, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if err := sm4CheckCBCIV(iv, blockSize); err != nil {
		return nil, err
	}

	paddingData := ZeroPadding(plainText, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, iv)

	cipherText := make([]byte, len(paddingData))

	blockMode.CryptBlocks(cipherText, paddingData)

	return cipherText, nil
}

// Sm4CbcDecryptZero decrypts SM4-CBC with zero-padding removal; does not mutate cipherText.
func Sm4CbcDecryptZero(cipherText, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if err := sm4CheckCBCIV(iv, blockSize); err != nil {
		return nil, err
	}

	if len(cipherText)%blockSize != 0 {
		return nil, fmt.Errorf("sm4 cbc: ciphertext length %d is not a multiple of block size %d", len(cipherText), blockSize)
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)

	plainBuf := make([]byte, len(cipherText))
	blockMode.CryptBlocks(plainBuf, cipherText)

	plainText, err := ZeroUnPadding(plainBuf)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
