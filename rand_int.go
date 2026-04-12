/**
 * @Author: lidonglin
 * @Description: Random int/float helpers via math/rand (not for secrets).
 * @File:  rand_int.go
 * @Version: 1.0.0
 * @Date: 2023/11/23 10:06
 */

package tutil

import "math/rand"

// RandBaseInt returns a uniform int in [base, base+n); if n <= 0 returns base (avoids rand.Intn panic). Not crypto-safe.
func RandBaseInt(base int, n int) int {
	if n <= 0 {
		return base
	}

	return base + rand.Intn(n)
}

// RandInt returns a uniform int in [0, n); if n <= 0 returns 0. Not crypto-safe.
func RandInt(n int) int {
	return RandBaseInt(0, n)
}

// RandFloat32 returns [0.0,1.0) from global math/rand. Not crypto-safe.
func RandFloat32() float32 {
	return rand.Float32()
}
