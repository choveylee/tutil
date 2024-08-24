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

func Sm4CbcEncrypt(plainText, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddingData := PKCS5Padding(plainText, block.BlockSize())

	blockMode := cipher.NewCBCEncrypter(block, iv)

	cipherText := make([]byte, len(paddingData))

	blockMode.CryptBlocks(cipherText, paddingData)

	return cipherText, nil
}

func Sm4CbcDecrypt(cipherText, key, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)

	blockMode.CryptBlocks(cipherText, cipherText)

	plainText, err := PKCS5UnPadding(cipherText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
