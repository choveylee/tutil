/**
 * @Author: lidonglin
 * @Description:
 * @File:  rand_int.go
 * @Version: 1.0.0
 * @Date: 2023/11/23 10:06
 */

package tutil

import (
	"math/rand"
	"time"
)

func init() {
	rand.NewSource(time.Now().UTC().UnixNano())
}

// RandBaseInt 随机base到base+n内的一个整数
func RandBaseInt(base int, n int) int {
	if n < 0 {
		return base
	}

	return base + rand.Intn(n)
}

// RandInt 随机0到n-1内的一个整数
func RandInt(n int) int {
	if n <= 0 {
		return 0
	}

	return rand.Intn(n)
}

// RandFloat32 随机1到1内的一个浮点数
func RandFloat32() float32 {
	return rand.Float32()
}
