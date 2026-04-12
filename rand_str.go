/**
 * @Author: lidonglin
 * @Description: Random strings via math/rand (not for passwords or tokens).
 * @File:  rand_str.go
 * @Version: 1.0.0
 * @Date: 2023/11/23 10:07
 */

package tutil

import "math/rand"

// randChar and randNum are byte alphabets used by RandCharStr and RandNumStr.
var (
	randChar = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	randNum  = []byte("0123456789")
)

// RandCharStr returns a string of n random ASCII digits and letters, or "" if n <= 0 (not cryptographically secure).
func RandCharStr(n int) string {
	if n <= 0 {
		return ""
	}

	data := make([]byte, n)

	charLen := len(randChar)

	for i := range data {
		data[i] = randChar[rand.Intn(charLen)]
	}

	return string(data)
}

// RandNumStr returns a string of n random decimal digits, or "" if n <= 0 (not cryptographically secure).
func RandNumStr(n int) string {
	if n <= 0 {
		return ""
	}

	data := make([]byte, n)

	digitLen := len(randNum)

	for i := range data {
		data[i] = randNum[rand.Intn(digitLen)]
	}

	return string(data)
}

// RandSourceStr returns a length-n string by sampling bytes from source with replacement, or "" if n <= 0 or source is empty (not cryptographically secure).
func RandSourceStr(source []byte, n int) string {
	if n <= 0 || len(source) == 0 {
		return ""
	}

	data := make([]byte, n)

	sourceLen := len(source)

	for i := range data {
		data[i] = source[rand.Intn(sourceLen)]
	}

	return string(data)
}
