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

// AesEncrypt encrypts plainText block-by-block with AES block.Encrypt.
// plainText length must be a multiple of the block size (16). Key length must be valid for aes.NewCipher (16/24/32).
// This is raw block encryption; prefer the padded ECB/CBC helpers for typical payloads.
func AesEncrypt(plainText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(plainText)%blockSize != 0 {
		return nil, fmt.Errorf("aes encrypt: plaintext length %d is not a multiple of block size %d", len(plainText), blockSize)
	}

	out := make([]byte, len(plainText))
	block.Encrypt(out, plainText)

	return out, nil
}

// DecryptAES decrypts ciphertext produced by AesEncrypt; length must be a multiple of the block size.
func DecryptAES(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(cipherText)%blockSize != 0 {
		return nil, fmt.Errorf("aes decrypt: ciphertext length %d is not a multiple of block size %d", len(cipherText), blockSize)
	}

	out := make([]byte, len(cipherText))
	block.Decrypt(out, cipherText)

	return out, nil
}

// ecbEncryptBlocks ECB-encrypts src into dst using block. len(src) must be a multiple of the block size; len(dst) >= len(src).
// Invalid input returns an error (no panic).
func ecbEncryptBlocks(block cipher.Block, dst, src []byte) error {
	bs := block.BlockSize()
	if bs <= 0 {
		return errors.New("ecb: invalid block size")
	}

	if len(src)%bs != 0 {
		return fmt.Errorf("ecb encrypt: input length %d is not a multiple of block size %d", len(src), bs)
	}

	if len(dst) < len(src) {
		return fmt.Errorf("ecb encrypt: output length %d is less than input length %d", len(dst), len(src))
	}

	for len(src) > 0 {
		block.Encrypt(dst, src[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}

	return nil
}

// ecbDecryptBlocks is the ECB decryption counterpart of ecbEncryptBlocks.
func ecbDecryptBlocks(block cipher.Block, dst, src []byte) error {
	bs := block.BlockSize()
	if bs <= 0 {
		return errors.New("ecb: invalid block size")
	}

	if len(src)%bs != 0 {
		return fmt.Errorf("ecb decrypt: input length %d is not a multiple of block size %d", len(src), bs)
	}

	if len(dst) < len(src) {
		return fmt.Errorf("ecb decrypt: output length %d is less than input length %d", len(dst), len(src))
	}

	for len(src) > 0 {
		block.Decrypt(dst, src[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}

	return nil
}

// ZeroPadding appends NUL bytes so the total length is a multiple of blockSize (if already aligned, appends a full block).
func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize

	padText := bytes.Repeat([]byte{0}, padding)

	return append(ciphertext, padText...)
}

// ZeroUnPadding strips trailing NUL bytes from plainText. Empty input is returned as-is.
func ZeroUnPadding(plainText []byte) ([]byte, error) {
	if len(plainText) == 0 {
		return plainText, nil
	}

	return bytes.TrimRight(plainText, "\x00"), nil
}

// PKCS7Padding appends PKCS#7 padding so length is a multiple of blockSize.
func PKCS7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize

	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(cipherText, padText...)
}

// PKCS7UnPadding removes PKCS#7 padding: last byte n must satisfy 1<=n<=blockSize and the last n bytes must equal n.
func PKCS7UnPadding(plainText []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}

	lens := len(plainText)
	if lens == 0 {
		return plainText, nil
	}

	unPadding := int(plainText[lens-1])
	if unPadding > lens || unPadding <= 0 || unPadding > blockSize {
		return nil, errors.New("invalid padding size")
	}

	startIndex := lens - unPadding
	paddingByte := byte(unPadding)

	for i := startIndex; i < lens; i++ {
		if plainText[i] != paddingByte {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}

	return plainText[:startIndex], nil
}

// GetAes128Key normalizes a string to 16 bytes for AES-128 only (not AES-192/256).
// Long keys are truncated; short keys are right-padded with ASCII '0'. Not a KDF.
func GetAes128Key(key string) string {
	if len(key) > 16 {
		return key[0:16]
	} else if len(key) < 16 {
		return fmt.Sprintf("%s%s", key, strings.Repeat("0", 16-len(key)))
	}

	return key
}

// AesEcbEncryptPKCS7 encrypts with AES-ECB and PKCS#7 padding. Key length selects AES-128/192/256.
// ECB is weak for general confidentiality; use only for interoperability with legacy systems.
func AesEcbEncryptPKCS7(plainText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

// AesEcbDecryptPKCS7 decrypts data encrypted with AesEcbEncryptPKCS7.
func AesEcbDecryptPKCS7(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

// AesEcbEncryptZero encrypts with AES-ECB and zero padding (ZeroPadding).
func AesEcbEncryptZero(plainText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

// AesEcbDecryptZero decrypts AES-ECB ciphertext with zero padding removal (ZeroUnPadding).
func AesEcbDecryptZero(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

// AesCbcEncryptPKCS7 encrypts with AES-CBC and PKCS#7 padding.
// If iv is nil or empty, the first blockSize bytes of key are used as IV (legacy); prefer a random unique IV.
func AesCbcEncryptPKCS7(plainText, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	plainText = PKCS7Padding(plainText, blockSize)

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

// AesCbcDecryptPKCS7 decrypts AES-CBC + PKCS#7. Empty iv uses the same default IV rule as AesCbcEncryptPKCS7.
func AesCbcDecryptPKCS7(cipherText, key, iv []byte) ([]byte, error) {
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

	blockSize := block.BlockSize()

	plainText, err = PKCS7UnPadding(plainText, blockSize)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// AesCbcEncryptZero encrypts with AES-CBC and zero padding. Empty iv behavior matches AesCbcEncryptPKCS7.
func AesCbcEncryptZero(plainText, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	plainText = ZeroPadding(plainText, blockSize)

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

// AesCbcDecryptZero decrypts AES-CBC with zero padding removal. Empty iv behavior matches AesCbcEncryptPKCS7.
func AesCbcDecryptZero(cipherText, key, iv []byte) ([]byte, error) {
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

	plainText, err = ZeroUnPadding(plainText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
