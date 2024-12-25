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
	"fmt"
	"strings"
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

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize

	padText := bytes.Repeat([]byte{0}, padding)

	return append(ciphertext, padText...)
}

func ZeroUnPadding(plainText []byte) ([]byte, error) {
	lens := len(plainText)
	if lens == 0 {
		return plainText, nil
	}

	return bytes.TrimFunc(plainText, func(r rune) bool {
		return r == rune(0)
	}), nil
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
	if unPadding > lens || unPadding <= 0 {
		return nil, errors.New("unpadding error")
	}

	return plainText[:(lens - unPadding)], nil
}

func GetAesKey(key string) string {
	if len(key) > 16 {
		return key[0:16]
	} else if len(key) < 16 {
		return fmt.Sprintf("%s%s", key, strings.Repeat("0", 16-len(key)))
	}

	return key
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

func AesCbcEncrypt(plainText, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	plainText = PKCS5Padding(plainText, blockSize)

	if len(iv) == 0 {
		iv = key[:blockSize]
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)

	cipherText := make([]byte, len(plainText))

	if len(plainText)%blockMode.BlockSize() != 0 {
		return nil, fmt.Errorf("input not full blocks")
	}

	blockMode.CryptBlocks(cipherText, plainText)

	return cipherText, nil
}

func AesCbcDecrypt(cipherText, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) == 0 {
		blockSize := block.BlockSize()

		iv = key[:blockSize]
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)

	plainText := make([]byte, len(cipherText))

	if len(plainText)%blockMode.BlockSize() != 0 {
		return nil, fmt.Errorf("input not full blocks")
	}

	blockMode.CryptBlocks(plainText, cipherText)

	plainText, err = PKCS5UnPadding(plainText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
