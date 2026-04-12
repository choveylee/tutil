/**
 * @Author: lidonglin
 * @Description: Random strings via math/rand (not for passwords or tokens).
 * @File:  rand_str.go
 * @Version: 1.0.0
 * @Date: 2023/11/23 10:07
 */

package tutil

import "math/rand"

// Alphabets for RandCharStr and RandNumStr.
var (
	randChar = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	randNum  = []byte("0123456789")
)

// RandCharStr returns n random digits and letters; "" if n <= 0. Not crypto-safe.
func RandCharStr(n int) string {
	if n <= 0 {
		return ""
	}

	data := make([]byte, n)

	lens := len(randChar)

	for i := range data {
		data[i] = randChar[rand.Intn(lens)]
	}

	return string(data)
}

// RandNumStr returns n random decimal digits; "" if n <= 0. Not crypto-safe.
func RandNumStr(n int) string {
	if n <= 0 {
		return ""
	}

	data := make([]byte, n)

	lens := len(randNum)

	for i := range data {
		data[i] = randNum[rand.Intn(lens)]
	}

	return string(data)
}

// RandSourceStr returns n bytes sampled uniformly from source (with replacement); "" if n <= 0 or source empty. Not crypto-safe.
func RandSourceStr(source []byte, n int) string {
	if n <= 0 || len(source) == 0 {
		return ""
	}

	data := make([]byte, n)

	lens := len(source)

	for i := range data {
		data[i] = source[rand.Intn(lens)]
	}

	return string(data)
}
