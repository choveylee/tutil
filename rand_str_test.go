package tutil

import (
	"strings"
	"testing"
)

// TestRandCharStr checks alphabet and n<=0 behavior for RandCharStr.
func TestRandCharStr(t *testing.T) {
	t.Parallel()
	if RandCharStr(0) != "" || RandCharStr(-1) != "" {
		t.Fatal("n<=0 should return empty")
	}
	s := RandCharStr(100)
	if len(s) != 100 {
		t.Fatalf("len=%d", len(s))
	}
	for _, r := range s {
		if strings.ContainsRune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", r) {
			continue
		}
		t.Fatalf("unexpected rune %q", r)
	}
}

// TestRandNumStr checks digit-only output and n<=0 for RandNumStr.
func TestRandNumStr(t *testing.T) {
	t.Parallel()
	if RandNumStr(0) != "" {
		t.Fatal("n=0")
	}
	s := RandNumStr(50)
	if len(s) != 50 {
		t.Fatalf("len=%d", len(s))
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			t.Fatalf("non-digit %q", r)
		}
	}
}

// TestRandSourceStr checks empty source, n<=0, and sampling from a small alphabet.
func TestRandSourceStr(t *testing.T) {
	t.Parallel()
	if RandSourceStr([]byte("abc"), 0) != "" {
		t.Fatal("n=0")
	}
	if RandSourceStr(nil, 5) != "" || RandSourceStr([]byte{}, 5) != "" {
		t.Fatal("empty source")
	}
	src := []byte("XY")
	s := RandSourceStr(src, 30)
	if len(s) != 30 {
		t.Fatalf("len=%d", len(s))
	}
	for _, r := range s {
		if r != 'X' && r != 'Y' {
			t.Fatalf("unexpected %q", r)
		}
	}
}
