/**
 * @Author: lidonglin
 * @Description:
 * @File:  rand_int.go
 * @Version: 1.0.0
 * @Date: 2023/11/23 10:06
 */

package tutil

import "math/rand"

// RandBaseInt returns a uniform integer in [base, base+n) as base+rand.Intn(n).
// If n <= 0 it returns base without calling rand (avoids rand.Intn(0) panic).
func RandBaseInt(base int, n int) int {
	if n <= 0 {
		return base
	}

	return base + rand.Intn(n)
}

// RandInt returns a uniform non-negative integer in [0, n). If n <= 0 it returns 0.
func RandInt(n int) int {
	if n <= 0 {
		return 0
	}

	return rand.Intn(n)
}

// RandFloat32 returns a float from the global math/rand source in [0.0, 1.0).
func RandFloat32() float32 {
	return rand.Float32()
}
