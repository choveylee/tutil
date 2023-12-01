/**
 * @Author: lidonglin
 * @Description:
 * @File:  encrypt_aes.go
 * @Version: 1.0.0
 * @Date: 2023/11/30 09:48
 */

package tutil

import (
	"bytes"
	"crypto/aes"
	"errors"
)

func AesEncrypt(plainText, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipherText := make([]byte, len(plainText))

	cipher.Encrypt(cipherText, plainText)

	return cipherText, nil
}

func DecryptAES(cipherText, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(cipherText))

	cipher.Decrypt(plainText, cipherText)

	return plainText, nil
}

func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize

	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(cipherText, padText...)
}

func PKCS5UnPadding(plainText []byte) ([]byte, error) {
	lens := len(plainText)
	if lens == 0 {
		return plainText, nil
	}

	// TODO verify padding
	unPadding := int(plainText[lens-1])
	if unPadding > lens {
		return nil, errors.New("unpadding error")
	}

	return plainText[:(lens - unPadding)], nil
}

func AesEcbEncrypt(plainText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	plainText = PKCS5Padding(plainText, blockSize)

	cipherText := make([]byte, len(plainText))

	block.Encrypt(cipherText, plainText)

	for len(plainText) > 0 {
		block.Decrypt(cipherText, plainText[:blockSize])

		plainText = plainText[blockSize:]
		cipherText = cipherText[blockSize:]
	}

	return cipherText, nil
}

func AesEcbDecrypt(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	plainText := make([]byte, len(cipherText))

	for len(cipherText) > 0 {
		block.Decrypt(plainText, cipherText[:blockSize])

		cipherText = cipherText[blockSize:]
		plainText = plainText[blockSize:]
	}

	plainText, err = PKCS5UnPadding(plainText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
