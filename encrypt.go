/**
 * @Author: lidonglin
 * @Description:
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

// Md5 returns the MD5 digest of data (16 bytes). Not for security-sensitive use; legacy/checksums only.
func Md5(data []byte) []byte {
	h := md5.New()
	h.Write(data)

	return h.Sum(nil)
}

// Sha1 returns the SHA-1 digest of data (20 bytes). Avoid for new security-sensitive designs.
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

// HmacSha256 returns HMAC-SHA256(key, data).
func HmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)

	return h.Sum(nil)
}

// HmacMd5 returns HMAC-MD5(key, data). Weak for integrity/auth as a sole primitive.
func HmacMd5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)

	return h.Sum(nil)
}
