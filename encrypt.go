/**
 * @Author: lidonglin
 * @Description: Hash and HMAC helpers; MD5/SHA-1 are legacy-only for security.
 * @File:  encrypt.go
 * @Version: 1.0.0
 * @Date: 2022/12/15 22:09
 */

package tutil

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
)

// Md5 returns the 16-byte MD5 digest (legacy checksums only, not collision-safe).
func Md5(data []byte) []byte {
	h := md5.New()
	h.Write(data)

	return h.Sum(nil)
}

// Sha1 returns the 20-byte SHA-1 digest (avoid for new security-sensitive use).
func Sha1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)

	return h.Sum(nil)
}

// HmacSha1 returns HMAC-SHA1(key, data).
func HmacSha1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)

	return h.Sum(nil)
}

// HmacSha256 returns HMAC-SHA256(key, data); preferred for new code.
func HmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)

	return h.Sum(nil)
}

// HmacMd5 returns HMAC-MD5(key, data) (legacy; prefer HmacSha256).
func HmacMd5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)

	return h.Sum(nil)
}
