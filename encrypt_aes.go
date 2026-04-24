package tutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"strings"
)

// aesCbcResolveIV returns iv when it is one block long, derives the legacy default IV from key
// when iv is empty, and rejects all other IV lengths.
func aesCbcResolveIV(block cipher.Block, key, iv []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	switch {
	case len(iv) == blockSize:
		return iv, nil
	case len(iv) == 0:
		if len(key) < blockSize {
			return nil, fmt.Errorf("aes cbc: key length %d cannot derive default IV, want at least %d", len(key), blockSize)
		}

		return key[:blockSize], nil
	default:
		return nil, fmt.Errorf("aes cbc: invalid IV length %d, want 0 or %d", len(iv), blockSize)
	}
}

// AesEncrypt encrypts a single AES block without block chaining.
// plaintext must be exactly one AES block, and key must be 16, 24, or 32 bytes.
func AesEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(plaintext) != blockSize {
		return nil, fmt.Errorf("aes: invalid plaintext length %d, want %d", len(plaintext), blockSize)
	}

	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)

	return ciphertext, nil
}

// AesDecrypt decrypts ciphertext produced by AesEncrypt.
// ciphertext must be exactly one AES block.
func AesDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(ciphertext) != blockSize {
		return nil, fmt.Errorf("aes: invalid ciphertext length %d, want %d", len(ciphertext), blockSize)
	}

	plaintext := make([]byte, len(ciphertext))
	block.Decrypt(plaintext, ciphertext)

	return plaintext, nil
}

// ecbEncryptBlocks encrypts src into dst using ECB mode.
// src must be block-aligned, and dst must be at least as long as src.
func ecbEncryptBlocks(block cipher.Block, dst, src []byte) error {
	blockSize := block.BlockSize()
	if blockSize <= 0 {
		return errors.New("aes ecb: invalid block size")
	}

	if len(src)%blockSize != 0 {
		return fmt.Errorf("aes ecb: invalid encrypt input length %d, want multiple of %d", len(src), blockSize)
	}

	if len(dst) < len(src) {
		return fmt.Errorf("aes ecb: encrypt destination length %d, want at least %d", len(dst), len(src))
	}

	for len(src) > 0 {
		block.Encrypt(dst, src[:blockSize])
		src = src[blockSize:]
		dst = dst[blockSize:]
	}

	return nil
}

// ecbDecryptBlocks decrypts src into dst using ECB mode.
// src must be block-aligned, and dst must be at least as long as src.
func ecbDecryptBlocks(block cipher.Block, dst, src []byte) error {
	blockSize := block.BlockSize()
	if blockSize <= 0 {
		return errors.New("aes ecb: invalid block size")
	}

	if len(src)%blockSize != 0 {
		return fmt.Errorf("aes ecb: invalid decrypt input length %d, want multiple of %d", len(src), blockSize)
	}

	if len(dst) < len(src) {
		return fmt.Errorf("aes ecb: decrypt destination length %d, want at least %d", len(dst), len(src))
	}

	for len(src) > 0 {
		block.Decrypt(dst, src[:blockSize])
		src = src[blockSize:]
		dst = dst[blockSize:]
	}

	return nil
}

// ZeroPadding appends zero bytes to plaintext until its length is a multiple of blockSize.
// If the length is already aligned, it appends one full block of zeros.
// It returns nil if blockSize is not positive.
// Zero padding is lossy for plaintext that already ends in zero bytes.
func ZeroPadding(plaintext []byte, blockSize int) []byte {
	if blockSize <= 0 {
		return nil
	}

	padding := blockSize - len(plaintext)%blockSize

	padText := bytes.Repeat([]byte{0}, padding)

	return append(plaintext, padText...)
}

// ZeroUnPadding removes trailing zero bytes from plaintext.
// It cannot distinguish padding zeros from data zeros; an empty slice is returned unchanged.
func ZeroUnPadding(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return plaintext, nil
	}

	return bytes.TrimRight(plaintext, "\x00"), nil
}

// PKCS7Padding appends PKCS #7 padding to data so that its length is a multiple of blockSize.
// It returns nil if blockSize is outside the PKCS #7 range [1, 255].
func PKCS7Padding(data []byte, blockSize int) []byte {
	if blockSize <= 0 || blockSize > 255 {
		return nil
	}

	padding := blockSize - len(data)%blockSize

	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(data, padText...)
}

// PKCS7UnPadding removes PKCS #7 padding from paddedData.
// paddedData must be non-empty and its length must be a multiple of blockSize.
func PKCS7UnPadding(paddedData []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, errors.New("pkcs7: invalid block size")
	}

	textLen := len(paddedData)
	if textLen == 0 {
		return nil, errors.New("pkcs7: empty padded data")
	}

	if textLen%blockSize != 0 {
		return nil, fmt.Errorf("pkcs7: invalid padded data length %d, want multiple of %d", textLen, blockSize)
	}

	padLen := int(paddedData[textLen-1])
	if padLen > textLen || padLen <= 0 || padLen > blockSize {
		return nil, errors.New("pkcs7: invalid padding length")
	}

	startIndex := textLen - padLen
	paddingByte := byte(padLen)

	for i := startIndex; i < textLen; i++ {
		if paddedData[i] != paddingByte {
			return nil, errors.New("pkcs7: invalid padding bytes")
		}
	}

	return paddedData[:startIndex], nil
}

// GetAes128Key returns a 16-byte string derived from key by truncation or right-padding with ASCII '0'.
// It does not perform key derivation; callers must not treat the result as a strengthened key.
func GetAes128Key(key string) string {
	if len(key) > 16 {
		return key[0:16]
	} else if len(key) < 16 {
		return fmt.Sprintf("%s%s", key, strings.Repeat("0", 16-len(key)))
	}

	return key
}

// AesEcbEncryptPKCS7 encrypts plaintext using AES in ECB mode with PKCS #7 padding.
// ECB mode provides weak confidentiality; the function exists for legacy interoperability.
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

// AesEcbDecryptPKCS7 decrypts ciphertext produced by AesEcbEncryptPKCS7 using the same key.
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

// AesEcbEncryptZero encrypts plaintext using AES in ECB mode after ZeroPadding.
// ECB mode provides weak confidentiality; the function exists for legacy use.
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

// AesEcbDecryptZero decrypts ciphertext produced by AesEcbEncryptZero and removes zero padding via ZeroUnPadding.
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

// AesCbcEncryptPKCS7 encrypts plaintext using AES-CBC with PKCS #7 padding.
// If iv is empty, the first block of key is used as the initialization vector (legacy, insecure).
// Otherwise iv must be exactly one block long; new designs should use a random IV.
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
		return nil, fmt.Errorf("aes cbc: invalid padded plaintext length %d, want multiple of %d", len(plaintext), blockMode.BlockSize())
	}

	blockMode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// AesCbcDecryptPKCS7 decrypts ciphertext produced by AesCbcEncryptPKCS7.
// The key and iv arguments must follow the same rules as for encryption.
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
		return nil, fmt.Errorf("aes cbc: invalid ciphertext length %d, want multiple of %d", len(ciphertext), blockSize)
	}

	blockMode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = PKCS7UnPadding(plaintext, blockSize)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// AesCbcEncryptZero encrypts plaintext using AES-CBC after ZeroPadding.
// Initialization vector handling matches AesCbcEncryptPKCS7.
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
		return nil, fmt.Errorf("aes cbc: invalid padded plaintext length %d, want multiple of %d", len(plaintext), blockMode.BlockSize())
	}

	blockMode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// AesCbcDecryptZero decrypts ciphertext produced by AesCbcEncryptZero and removes zero padding via ZeroUnPadding.
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
		return nil, fmt.Errorf("aes cbc: invalid ciphertext length %d, want multiple of %d", len(ciphertext), blockSize)
	}

	blockMode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = ZeroUnPadding(plaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
