package tutil

import "math/rand"

// RandBaseInt returns a pseudo-random integer in the half-open interval
// [base, base+n) using math/rand. If n is less than or equal to zero, it
// returns base. The result is not suitable for cryptographic use.
func RandBaseInt(base int, n int) int {
	if n <= 0 {
		return base
	}

	return base + rand.Intn(n)
}

// RandInt returns a pseudo-random integer in the half-open interval [0, n)
// using math/rand. If n is less than or equal to zero, it returns zero. The
// result is not suitable for cryptographic use.
func RandInt(n int) int {
	return RandBaseInt(0, n)
}

// RandFloat32 returns a pseudo-random float32 in the half-open interval
// [0.0, 1.0) from the global math/rand source.
// The result is not suitable for cryptographic use.
func RandFloat32() float32 {
	return rand.Float32()
}
