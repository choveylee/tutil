package tutil

import (
	"math"
	"testing"
)

// TestRandBaseInt checks RandBaseInt boundary behavior and sample range.
func TestRandBaseInt(t *testing.T) {
	t.Parallel()
	if got := RandBaseInt(10, 0); got != 10 {
		t.Fatalf("n=0: got %d want 10", got)
	}
	if got := RandBaseInt(10, -1); got != 10 {
		t.Fatalf("n<0: got %d want 10", got)
	}
	for range 200 {
		v := RandBaseInt(100, 5)
		if v < 100 || v > 104 {
			t.Fatalf("out of range [100,104]: %d", v)
		}
	}
}

// TestRandInt checks RandInt for n<=0 and sample range.
func TestRandInt(t *testing.T) {
	t.Parallel()
	if RandInt(0) != 0 || RandInt(-1) != 0 {
		t.Fatal("n<=0 should return 0")
	}
	for range 200 {
		v := RandInt(10)
		if v < 0 || v > 9 {
			t.Fatalf("out of range: %d", v)
		}
	}
}

// TestRandFloat32 checks values lie in [0,1) and are finite.
func TestRandFloat32(t *testing.T) {
	t.Parallel()
	for range 200 {
		v := RandFloat32()
		if v < 0 || v >= 1 {
			t.Fatalf("Float32 out of [0,1): %v", v)
		}
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			t.Fatal("non-finite float")
		}
	}
}
