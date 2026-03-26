package tutil

import (
	"bytes"
	"testing"
)

// TestGetAes128Key checks padding, truncation, and 16-byte normalization.
func TestGetAes128Key(t *testing.T) {
	t.Parallel()
	if got := GetAes128Key("abcdefghijklmnop"); got != "abcdefghijklmnop" {
		t.Fatal(got)
	}
	if got := GetAes128Key("short"); len(got) != 16 || got != "short00000000000" {
		t.Fatalf("got %q", got)
	}
	if got := GetAes128Key("verylongsecretkeyhere"); got != "verylongsecretke" {
		t.Fatalf("got %q", got)
	}
}

// TestPKCS7Padding_Unpadding checks PKCS#7 padding round-trip and error cases.
func TestPKCS7Padding_Unpadding(t *testing.T) {
	t.Parallel()
	bs := 16
	p := PKCS7Padding([]byte("hello"), bs)
	if len(p)%bs != 0 {
		t.Fatal("not aligned")
	}
	out, err := PKCS7UnPadding(p, bs)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello" {
		t.Fatal(string(out))
	}
	if _, err := PKCS7UnPadding([]byte{1, 2, 3}, bs); err == nil {
		t.Fatal("bad len")
	}
	if _, err := PKCS7UnPadding([]byte{0x10}, 16); err == nil {
		t.Fatal("invalid padding byte vs length")
	}
	if _, err := PKCS7UnPadding([]byte("hello"), 0); err == nil {
		t.Fatal("blockSize 0")
	}
}

// TestZeroPadding_Unpadding checks zero-padding alignment and unpadding prefix.
func TestZeroPadding_Unpadding(t *testing.T) {
	t.Parallel()
	p := ZeroPadding([]byte("ab\x00"), 16)
	out, err := ZeroUnPadding(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("ab")) {
		t.Fatalf("%x", out)
	}
}

// TestAesEncrypt_DecryptAES_Block checks one-block ECB-equivalent encrypt/decrypt and alignment errors.
func TestAesEncrypt_DecryptAES_Block(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte("k"), 16)
	pt := bytes.Repeat([]byte("p"), 16)
	ct, err := AesEncrypt(pt, key)
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := DecryptAES(ct, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, pt2) {
		t.Fatal("round-trip")
	}
	if _, err := AesEncrypt([]byte("short"), key); err == nil {
		t.Fatal("want align error")
	}
}

// TestAesEcbPkcs7_RoundTrip checks AES-ECB with PKCS#7 padding round-trip.
func TestAesEcbPkcs7_RoundTrip(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{7}, 16)
	msg := []byte("hello aes ecb pkcs7")
	ct, err := AesEcbEncryptPKCS7(msg, key)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := AesEcbDecryptPKCS7(ct, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, pt) {
		t.Fatal("ecb pkcs7 mismatch")
	}
	if _, err := AesEcbDecryptPKCS7([]byte{1, 2, 3}, key); err == nil {
		t.Fatal("bad ciphertext length")
	}
}

// TestAesEcbZero_RoundTrip checks AES-ECB with zero padding round-trip.
func TestAesEcbZero_RoundTrip(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{9}, 16)
	msg := []byte("zero pad")
	ct, err := AesEcbEncryptZero(msg, key)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := AesEcbDecryptZero(ct, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, pt) {
		t.Fatal("mismatch")
	}
}

// TestAesCbcPkcs7_RoundTrip checks AES-CBC with PKCS#7 padding round-trip.
func TestAesCbcPkcs7_RoundTrip(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{3}, 16)
	iv := bytes.Repeat([]byte{5}, 16)
	msg := []byte("cbc pkcs7 message")
	ct, err := AesCbcEncryptPKCS7(msg, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := AesCbcDecryptPKCS7(ct, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, pt) {
		t.Fatal("cbc pkcs7")
	}
}

// TestAesCbcPkcs7_EmptyIV ensures nil IV uses the package’s legacy zero IV behavior.
func TestAesCbcPkcs7_EmptyIV(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{1}, 16)
	msg := []byte("x")
	ct, err := AesCbcEncryptPKCS7(msg, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := AesCbcDecryptPKCS7(ct, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, pt) {
		t.Fatal("empty iv compat")
	}
}

// TestAesCbcZero_RoundTrip checks AES-CBC with zero padding round-trip.
func TestAesCbcZero_RoundTrip(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{2}, 16)
	iv := bytes.Repeat([]byte{4}, 16)
	msg := []byte("cbc zero")
	ct, err := AesCbcEncryptZero(msg, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := AesCbcDecryptZero(ct, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, pt) {
		t.Fatal("cbc zero")
	}
}
