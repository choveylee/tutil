package tutil

import "math/rand"

// randChar and randNum are the character sets used by RandCharStr and
// RandNumStr.
var (
	randChar = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	randNum  = []byte("0123456789")
)

// RandCharStr returns a string of length n containing pseudo-random ASCII
// letters and decimal digits using math/rand. If n is less than or equal to
// zero, it returns an empty string. The result is not suitable for
// cryptographic use.
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

// RandNumStr returns a string of length n containing pseudo-random decimal
// digits using math/rand. If n is less than or equal to zero, it returns an
// empty string. The result is not suitable for cryptographic use.
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

// RandSourceStr returns a string of length n by sampling uniformly with
// replacement from source using math/rand. If n is less than or equal to zero
// or source is empty, it returns an empty string. The result is not suitable
// for cryptographic use.
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
