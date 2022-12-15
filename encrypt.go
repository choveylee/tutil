/**
 * @Author: lidonglin
 * @Description:
 * @File:  encrypt.go
 * @Version: 1.0.0
 * @Date: 2022/12/15 22:09
 */

package tutil

import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
)

func Md5(data string) string {
	h := md5.New()
	h.Write([]byte(data))

	return fmt.Sprintf("%x", h.Sum(nil))
}

func Sha1(data string) string {
	h := sha1.New() // md5加密类似md5.New()
	h.Write([]byte(data))

	return fmt.Sprintf("%x", h.Sum(nil))
}
