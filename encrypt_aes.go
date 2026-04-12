/**
 * @Author: lidonglin
 * @Description: AES block/ECB/CBC helpers (legacy; prefer AES-GCM for new designs).
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

// aesCbcResolveIV returns iv when len(iv) equals the block size, or key[:blockSize] when iv is empty (legacy default), or an error otherwise.
func aesCbcResolveIV(block cipher.Block, key, iv []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	switch {
	case len(iv) == blockSize:
		return iv, nil
	case len(iv) == 0:
		if len(key) < blockSize {
			return nil, fmt.Errorf("aes cbc: key length %d is insufficient to derive default IV (required at least %d bytes)", len(key), blockSize)
		}

		return key[:blockSize], nil
	default:
		return nil, fmt.Errorf("aes cbc: IV length is %d; must be 0 or %d bytes", len(iv), blockSize)
	}
}

// AesEncrypt encrypts plaintext with AES in ECB block mode (no mode chaining). The plaintext length must be a multiple of the block size; key must be 16, 24, or 32 bytes.
func AesEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(plaintext)%blockSize != 0 {
		return nil, fmt.Errorf("aes: plaintext length %d must be a multiple of block size %d", len(plaintext), blockSize)
	}

	out := make([]byte, len(plaintext))
	block.Encrypt(out, plaintext)

	return out, nil
}

// AesDecrypt decrypts ciphertext produced by AesEncrypt. The ciphertext length must be a multiple of the block size.
func AesDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("aes: ciphertext length %d must be a multiple of block size %d", len(ciphertext), blockSize)
	}

	out := make([]byte, len(ciphertext))
	block.Decrypt(out, ciphertext)

	return out, nil
}

// ecbEncryptBlocks ECB-encrypts src into dst blockwise. len(src) must be a multiple of the block size and len(dst) must be at least len(src).
func ecbEncryptBlocks(block cipher.Block, dst, src []byte) error {
	blockSize := block.BlockSize()
	if blockSize <= 0 {
		return errors.New("aes ecb: invalid block size")
	}

	if len(src)%blockSize != 0 {
		return fmt.Errorf("aes ecb encrypt: input length %d must be a multiple of block size %d", len(src), blockSize)
	}

	if len(dst) < len(src) {
		return fmt.Errorf("aes ecb encrypt: destination buffer length %d is less than required %d", len(dst), len(src))
	}

	for len(src) > 0 {
		block.Encrypt(dst, src[:blockSize])
		src = src[blockSize:]
		dst = dst[blockSize:]
	}

	return nil
}

// ecbDecryptBlocks ECB-decrypts src into dst using the same length rules as ecbEncryptBlocks.
func ecbDecryptBlocks(block cipher.Block, dst, src []byte) error {
	blockSize := block.BlockSize()
	if blockSize <= 0 {
		return errors.New("aes ecb: invalid block size")
	}

	if len(src)%blockSize != 0 {
		return fmt.Errorf("aes ecb decrypt: input length %d must be a multiple of block size %d", len(src), blockSize)
	}

	if len(dst) < len(src) {
		return fmt.Errorf("aes ecb decrypt: destination buffer length %d is less than required %d", len(dst), len(src))
	}

	for len(src) > 0 {
		block.Decrypt(dst, src[:blockSize])
		src = src[blockSize:]
		dst = dst[blockSize:]
	}

	return nil
}

// ZeroPadding appends zero bytes to plaintext so its length is a multiple of blockSize (if already aligned, appends one full block).
func ZeroPadding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize

	padText := bytes.Repeat([]byte{0}, padding)

	return append(plaintext, padText...)
}

// ZeroUnPadding removes trailing NUL bytes from plaintext. An empty slice is returned unchanged.
func ZeroUnPadding(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return plaintext, nil
	}

	return bytes.TrimRight(plaintext, "\x00"), nil
}

// PKCS7Padding appends PKCS#7 padding to ciphertext so its length is a multiple of blockSize.
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize

	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(ciphertext, padText...)
}

// PKCS7UnPadding removes PKCS#7 padding from plaintext or returns an error if padding is invalid.
func PKCS7UnPadding(plaintext []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("pkcs7: invalid block size")
	}

	textLen := len(plaintext)
	if textLen == 0 {
		return plaintext, nil
	}

	padLen := int(plaintext[textLen-1])
	if padLen > textLen || padLen <= 0 || padLen > blockSize {
		return nil, errors.New("pkcs7: invalid padding length")
	}

	startIndex := textLen - padLen
	paddingByte := byte(padLen)

	for i := startIndex; i < textLen; i++ {
		if plaintext[i] != paddingByte {
			return nil, errors.New("pkcs7: padding is malformed or corrupted")
		}
	}

	return plaintext[:startIndex], nil
}

// GetAes128Key returns a 16-byte string view of key by truncation or right-padding with ASCII '0' (not a key derivation function).
func GetAes128Key(key string) string {
	if len(key) > 16 {
		return key[0:16]
	} else if len(key) < 16 {
		return fmt.Sprintf("%s%s", key, strings.Repeat("0", 16-len(key)))
	}

	return key
}

// AesEcbEncryptPKCS7 encrypts plaintext with AES in ECB mode and PKCS#7 padding (weak mode; legacy interoperability only).
func AesEcbEncryptPKCS7(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

// AesEcbDecryptPKCS7 decrypts ciphertext produced by AesEcbEncryptPKCS7.
func AesEcbDecryptPKCS7(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

// AesEcbEncryptZero encrypts plaintext with AES-ECB after ZeroPadding (weak mode; legacy use only).
func AesEcbEncryptZero(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

// AesEcbDecryptZero decrypts ciphertext produced by AesEcbEncryptZero and applies ZeroUnPadding.
func AesEcbDecryptZero(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

// AesCbcEncryptPKCS7 encrypts plaintext with AES-CBC and PKCS#7 padding. If iv is empty, the first block of key is used as IV (insecure legacy); otherwise iv must be one block long—prefer a random IV for new data.
func AesCbcEncryptPKCS7(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	plaintext = PKCS7Padding(plaintext, blockSize)

	iv, err = aesCbcResolveIV(block, key, iv)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(plaintext))

	if len(plaintext)%blockMode.BlockSize() != 0 {
		return nil, fmt.Errorf("aes cbc: plaintext length %d must be a multiple of block size %d", len(plaintext), blockMode.BlockSize())
	}

	blockMode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// AesCbcDecryptPKCS7 decrypts ciphertext produced by AesCbcEncryptPKCS7 using the same IV rules.
func AesCbcDecryptPKCS7(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	iv, err = aesCbcResolveIV(block, key, iv)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))

	if len(plaintext)%blockMode.BlockSize() != 0 {
		return nil, fmt.Errorf("aes cbc: ciphertext length %d must be a multiple of block size %d", len(ciphertext), blockSize)
	}

	blockMode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = PKCS7UnPadding(plaintext, blockSize)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// AesCbcEncryptZero encrypts plaintext with AES-CBC after ZeroPadding; IV handling matches AesCbcEncryptPKCS7.
func AesCbcEncryptZero(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	plaintext = ZeroPadding(plaintext, blockSize)

	iv, err = aesCbcResolveIV(block, key, iv)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(plaintext))

	if len(plaintext)%blockMode.BlockSize() != 0 {
		return nil, fmt.Errorf("aes cbc: padded plaintext length %d must be a multiple of block size %d", len(plaintext), blockMode.BlockSize())
	}

	blockMode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// AesCbcDecryptZero decrypts ciphertext produced by AesCbcEncryptZero and applies ZeroUnPadding.
func AesCbcDecryptZero(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	iv, err = aesCbcResolveIV(block, key, iv)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))

	if len(plaintext)%blockMode.BlockSize() != 0 {
		return nil, fmt.Errorf("aes cbc: ciphertext length %d must be a multiple of block size %d", len(ciphertext), blockSize)
	}

	blockMode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = ZeroUnPadding(plaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
