/**
 * @Author: lidonglin
 * @Description: Random int/float helpers via math/rand (not for secrets).
 * @File:  rand_int.go
 * @Version: 1.0.0
 * @Date: 2023/11/23 10:06
 */

package tutil

import "math/rand"

// RandBaseInt returns a uniform integer in [base, base+n); if n <= 0 it returns base (not cryptographically secure).
func RandBaseInt(base int, n int) int {
	if n <= 0 {
		return base
	}

	return base + rand.Intn(n)
}

// RandInt returns a uniform integer in [0, n); if n <= 0 it returns 0 (not cryptographically secure).
func RandInt(n int) int {
	return RandBaseInt(0, n)
}

// RandFloat32 returns a float32 in [0.0, 1.0) from the global math/rand source (not cryptographically secure).
func RandFloat32() float32 {
	return rand.Float32()
}
