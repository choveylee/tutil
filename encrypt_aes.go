/**
 * @Author: lidonglin
 * @Description:
 * @File:  encrypt_aes.go
 * @Version: 1.0.0
 * @Date: 2023/10/31 15:55
 */

package tutil

import (
	"bytes"
	"crypto/aes"
)

func padding(data []byte) []byte {
	paddingCount := aes.BlockSize - len(data)%aes.BlockSize

	if paddingCount == 0 {
		return data
	}

	//填充数据
	return append(data, bytes.Repeat([]byte{byte(0)}, paddingCount)...)
}

func AesEcbEncrypt(origData []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	origData = padding(origData)

	encryptedData := make([]byte, len(origData))

	tmpData := make([]byte, aes.BlockSize)

	//分组分块加密
	for index := 0; index < len(encryptedData); index += aes.BlockSize {
		cipher.Encrypt(tmpData, encryptedData[index:index+aes.BlockSize])
		copy(encryptedData, tmpData)
	}

	return encryptedData, nil
}

func unPadding(data []byte) []byte {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			return data[:i+1]
		}
	}

	return nil
}

func AesEcbDecrypt(encryptedData []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	origData := make([]byte, len(encryptedData))

	tmpData := make([]byte, aes.BlockSize)

	//分组分块解密
	for index := 0; index < len(encryptedData); index += aes.BlockSize {
		cipher.Decrypt(tmpData, encryptedData[index:index+aes.BlockSize])
		copy(origData, tmpData)
	}

	return unPadding(origData), nil
}
