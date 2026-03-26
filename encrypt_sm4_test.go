package tutil

import (
	"bytes"
	"testing"
)

// sm4Key and sm4IV are fixed 16-byte test vectors for SM4 tests.
var sm4Key = bytes.Repeat([]byte{0xab}, 16)
var sm4IV = bytes.Repeat([]byte{0xcd}, 16)

// TestSm4EcbPkcs7_RoundTrip checks SM4-ECB with PKCS#7 padding.
func TestSm4EcbPkcs7_RoundTrip(t *testing.T) {
	t.Parallel()
	msg := []byte("sm4 ecb pkcs7")
	ct, err := Sm4EcbEncryptPKCS7(msg, sm4Key)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Sm4EcbDecryptPKCS7(ct, sm4Key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, pt) {
		t.Fatal("ecb pkcs7")
	}
	if _, err := Sm4EcbDecryptPKCS7([]byte{1}, sm4Key); err == nil {
		t.Fatal("bad block length")
	}
}

// TestSm4EcbZero_RoundTrip checks SM4-ECB with zero padding.
func TestSm4EcbZero_RoundTrip(t *testing.T) {
	t.Parallel()
	msg := []byte("sm4 zero")
	ct, err := Sm4EcbEncryptZero(msg, sm4Key)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Sm4EcbDecryptZero(ct, sm4Key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, pt) {
		t.Fatal("ecb zero")
	}
}

// TestSm4CbcPkcs7_RoundTrip checks SM4-CBC with PKCS#7 padding.
func TestSm4CbcPkcs7_RoundTrip(t *testing.T) {
	t.Parallel()
	msg := []byte("sm4 cbc pkcs7 payload")
	ct, err := Sm4CbcEncryptPKCS7(msg, sm4Key, sm4IV)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Sm4CbcDecryptPKCS7(ct, sm4Key, sm4IV)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, pt) {
		t.Fatal("cbc pkcs7")
	}
}

// TestSm4Cbc_IV_And_CipherLen checks IV length, ciphertext alignment, and that decrypt does not mutate the caller buffer.
func TestSm4Cbc_IV_And_CipherLen(t *testing.T) {
	t.Parallel()
	if _, err := Sm4CbcEncryptPKCS7([]byte("x"), sm4Key, []byte{1}); err == nil {
		t.Fatal("short iv should error")
	}
	if _, err := Sm4CbcDecryptPKCS7([]byte{1}, sm4Key, sm4IV); err == nil {
		t.Fatal("unaligned ciphertext")
	}
	ct, _ := Sm4CbcEncryptPKCS7([]byte("ok"), sm4Key, sm4IV)
	orig := append([]byte(nil), ct...)
	pt, err := Sm4CbcDecryptPKCS7(ct, sm4Key, sm4IV)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(orig, ct) {
		t.Fatal("decrypt must not modify caller ciphertext buffer")
	}
	if string(pt) != "ok" {
		t.Fatal(string(pt))
	}
}

// TestSm4CbcZero_RoundTrip checks SM4-CBC with zero padding.
func TestSm4CbcZero_RoundTrip(t *testing.T) {
	t.Parallel()
	msg := []byte("cbc zero")
	ct, err := Sm4CbcEncryptZero(msg, sm4Key, sm4IV)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Sm4CbcDecryptZero(ct, sm4Key, sm4IV)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, pt) {
		t.Fatal("cbc zero")
	}
}
