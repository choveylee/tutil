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
	"crypto/cipher"
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

type ecbBlockMode struct {
	block cipher.Block

	blockSize int
}

func newEcbBlockMode(block cipher.Block) *ecbBlockMode {
	return &ecbBlockMode{
		block:     block,
		blockSize: block.BlockSize(),
	}
}

type ecbEncryptor ecbBlockMode

func newEcbEncryptor(block cipher.Block) cipher.BlockMode {
	return (*ecbEncryptor)(newEcbBlockMode(block))
}

func (ecb *ecbEncryptor) BlockSize() int {
	return ecb.blockSize
}

func (ecb *ecbEncryptor) CryptBlocks(dst, src []byte) {
	if len(src)%ecb.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		ecb.block.Encrypt(dst, src[:ecb.blockSize])
		src = src[ecb.blockSize:]
		dst = dst[ecb.blockSize:]
	}
}

type ecbDecryptor ecbBlockMode

func newEcbDecryptor(block cipher.Block) cipher.BlockMode {
	return (*ecbDecryptor)(newEcbBlockMode(block))
}

func (ecb *ecbDecryptor) BlockSize() int {
	return ecb.blockSize
}

func (ecb *ecbDecryptor) CryptBlocks(dst, src []byte) {
	if len(src)%ecb.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}

	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for len(src) > 0 {
		ecb.block.Decrypt(dst, src[:ecb.blockSize])
		src = src[ecb.blockSize:]
		dst = dst[ecb.blockSize:]
	}
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

	blockMode := newEcbEncryptor(block)

	plainText = PKCS5Padding(plainText, block.BlockSize())

	cipherText := make([]byte, len(plainText))

	blockMode.CryptBlocks(cipherText, plainText)

	return cipherText, nil
}

func AesEcbDecrypt(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(cipherText))

	blockMode := newEcbDecryptor(block)

	blockMode.CryptBlocks(plainText, cipherText)

	plainText, err = PKCS5UnPadding(plainText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
