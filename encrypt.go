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
)

func Md5(data []byte) []byte {
	h := md5.New()
	h.Write([]byte(data))

	return h.Sum(nil)
}

func Sha1(data []byte) []byte {
	h := sha1.New()
	h.Write([]byte(data))

	return h.Sum(nil)
}

func HmacSha1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)

	return h.Sum(nil)
}

func HmacMd5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)

	return h.Sum(nil)
}
