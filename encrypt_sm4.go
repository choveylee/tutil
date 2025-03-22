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

	"github.com/tjfoc/gmsm/sm4"
)

func Sm4EcbEncryptPKCS7(plainText, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := newEcbEncryptor(block)

	plainText = PKCS7Padding(plainText, block.BlockSize())

	cipherText := make([]byte, len(plainText))

	blockMode.CryptBlocks(cipherText, plainText)

	return cipherText, nil
}

func Sm4EcbDecryptPKCS7(cipherText, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(cipherText))

	blockMode := newEcbDecryptor(block)

	blockMode.CryptBlocks(plainText, cipherText)

	plainText, err = PKCS7UnPadding(plainText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func Sm4EcbEncryptZero(plainText, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := newEcbEncryptor(block)

	plainText = ZeroPadding(plainText, block.BlockSize())

	cipherText := make([]byte, len(plainText))

	blockMode.CryptBlocks(cipherText, plainText)

	return cipherText, nil
}

func Sm4EcbDecryptZero(cipherText, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(cipherText))

	blockMode := newEcbDecryptor(block)

	blockMode.CryptBlocks(plainText, cipherText)

	plainText, err = ZeroUnPadding(plainText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func Sm4CbcEncryptPKCS7(plainText, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddingData := PKCS7Padding(plainText, block.BlockSize())

	blockMode := cipher.NewCBCEncrypter(block, iv)

	cipherText := make([]byte, len(paddingData))

	blockMode.CryptBlocks(cipherText, paddingData)

	return cipherText, nil
}

func Sm4CbcDecryptPKCS7(cipherText, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)

	blockMode.CryptBlocks(cipherText, cipherText)

	plainText, err := PKCS7UnPadding(cipherText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func Sm4CbcEncryptZero(plainText, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddingData := ZeroPadding(plainText, block.BlockSize())

	blockMode := cipher.NewCBCEncrypter(block, iv)

	cipherText := make([]byte, len(paddingData))

	blockMode.CryptBlocks(cipherText, paddingData)

	return cipherText, nil
}

func Sm4CbcDecryptZero(cipherText, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)

	blockMode.CryptBlocks(cipherText, cipherText)

	plainText, err := ZeroUnPadding(cipherText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
