/**
 * @Author: lidonglin
 * @Description:
 * @File:  rand_str.go
 * @Version: 1.0.0
 * @Date: 2023/11/23 10:07
 */

package tutil

import "math/rand"

// Character alphabets for random string helpers (package private).
var (
	randChar = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	randNum  = []byte("0123456789")
)

// RandCharStr returns a random string of length n from digits and ASCII letters.
// Returns "" if n <= 0. Uses global math/rand; not cryptographically secure.
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

// RandNumStr returns a random decimal digit string of length n. Returns "" if n <= 0. Not cryptographically secure.
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

// RandSourceStr returns a length-n string by sampling bytes from source with replacement.
// Returns "" if n <= 0 or source is empty. Not cryptographically secure.
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
