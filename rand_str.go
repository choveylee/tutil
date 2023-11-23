/**
 * @Author: lidonglin
 * @Description:
 * @File:  rand_str.go
 * @Version: 1.0.0
 * @Date: 2023/11/23 10:07
 */

package tutil

import (
	"math/rand"
)

func RandCharStr(n int) string {
	bytesInit := []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	data := make([]byte, 0)

	for i := 0; i < n; i++ {
		data = append(data, bytesInit[rand.Intn(len(bytesInit))])
	}

	return string(data)
}

func RandNumStr(n int) string {
	bytesInit := []byte("0123456789")

	data := make([]byte, 0)

	for i := 0; i < n; i++ {
		data = append(data, bytesInit[rand.Intn(len(bytesInit))])
	}

	return string(data)
}

func RandSourceStr(source []byte, n int) string {
	data := make([]byte, 0)

	for i := 0; i < n; i++ {
		data = append(data, source[rand.Intn(len(source))])
	}

	return string(data)
}
