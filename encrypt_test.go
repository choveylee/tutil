package tutil

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestMd5 compares Md5 of empty input to a known vector.
func TestMd5(t *testing.T) {
	t.Parallel()
	want, _ := hex.DecodeString("d41d8cd98f00b204e9800998ecf8427e")
	if got := Md5(nil); !bytes.Equal(got, want) {
		t.Fatalf("empty md5: %x", got)
	}
}

// TestSha1 compares Sha1 of empty input to a known vector.
func TestSha1(t *testing.T) {
	t.Parallel()
	want, _ := hex.DecodeString("da39a3ee5e6b4b0d3255bfef95601890afd80709")
	if got := Sha1(nil); !bytes.Equal(got, want) {
		t.Fatalf("empty sha1: %x", got)
	}
}

// TestHmacSha256 checks digest length and determinism.
func TestHmacSha256(t *testing.T) {
	t.Parallel()
	key := []byte("key")
	data := []byte("data")
	sum := HmacSha256(key, data)
	if len(sum) != 32 {
		t.Fatalf("len=%d", len(sum))
	}
	sum2 := HmacSha256(key, data)
	if !bytes.Equal(sum, sum2) {
		t.Fatal("not deterministic")
	}
}

// TestHmacSha1_HmacMd5 checks MAC output lengths for SHA1 and MD5 variants.
func TestHmacSha1_HmacMd5(t *testing.T) {
	t.Parallel()
	if len(HmacSha1([]byte("k"), []byte("d"))) != 20 {
		t.Fatal("sha1 mac len")
	}
	if len(HmacMd5([]byte("k"), []byte("d"))) != 16 {
		t.Fatal("md5 mac len")
	}
}
