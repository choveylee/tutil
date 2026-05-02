package tutil

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
)

// Md5 computes the 16-byte MD5 digest of data and returns it.
// It is intended only for legacy checksums, not for collision-resistant security.
func Md5(data []byte) []byte {
	h := md5.New()
	h.Write(data)

	return h.Sum(nil)
}

// Sha1 computes the 20-byte SHA-1 digest of data and returns it.
// New security-sensitive designs should prefer stronger hashes.
func Sha1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)

	return h.Sum(nil)
}

// HmacSha1 computes the HMAC-SHA1 authentication code for data using key.
func HmacSha1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)

	return h.Sum(nil)
}

// HmacSha256 computes the HMAC-SHA256 authentication code for data using key.
// It is the preferred choice for new code among the HMAC functions in this package.
func HmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)

	return h.Sum(nil)
}

// HmacMd5 computes the HMAC-MD5 authentication code for data using key.
// Prefer HmacSha256 for new code.
func HmacMd5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)

	return h.Sum(nil)
}
