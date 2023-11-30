/**
 * @Author: lidonglin
 * @Description:
 * @File:  encrypt_aes.go
 * @Version: 1.0.0
 * @Date: 2023/11/30 09:48
 */

package tutil

import (
	"crypto/aes"
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
