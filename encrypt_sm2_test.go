package tutil

import (
	"bytes"
	"testing"
)

// TestGenSm2KeyPair_Sm2EncryptDecrypt checks key generation hex output and encrypt/decrypt round-trip.
func TestGenSm2KeyPair_Sm2EncryptDecrypt(t *testing.T) {
	t.Parallel()
	privHex, pubHex, err := GenSm2KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(privHex) == 0 || len(pubHex) == 0 {
		t.Fatal("empty key hex")
	}
	msg := []byte("sm2 round-trip")
	ct, err := Sm2Encrypt(msg, pubHex)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Sm2Decrypt(ct, privHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, pt) {
		t.Fatal("sm2 mismatch")
	}
}
