package tutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// rsaTestPEMs builds PKCS#1 RSA public and private PEM blocks for tests.
func rsaTestPEMs(t *testing.T) (pubPEM, privPEM []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	privDER := x509.MarshalPKCS1PrivateKey(k)
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA Private Key", Bytes: privDER})
	pubDER := x509.MarshalPKCS1PublicKey(&k.PublicKey)
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA Public Key", Bytes: pubDER})
	return pubPEM, privPEM
}

// TestRsaEncryptDecrypt_PKCS1 checks PKCS#1 encrypt/decrypt round-trip.
func TestRsaEncryptDecrypt_PKCS1(t *testing.T) {
	ResetRsaKeyType(PublicKeyPKCS1, PrivateKeyPKCS1)
	pub, priv := rsaTestPEMs(t)
	msg := []byte("hello rsa")
	ct, err := RsaEncrypt(msg, pub)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := RsaDecrypt(ct, priv)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != string(msg) {
		t.Fatal("round-trip")
	}
}

// TestRsaSignVerify checks signature generation, verification, and tamper detection.
func TestRsaSignVerify(t *testing.T) {
	ResetRsaKeyType(PublicKeyPKCS1, PrivateKeyPKCS1)
	pub, priv := rsaTestPEMs(t)
	digest := []byte("payload-bytes")
	sig, err := RsaSignature(digest, priv)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := RsaSignatureVerify(digest, sig, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("verify failed")
	}
	bad := make([]byte, len(sig))
	copy(bad, sig)
	bad[0] ^= 0xff
	ok, err = RsaSignatureVerify(digest, bad, pub)
	if ok {
		t.Fatal("tampered sig should not verify")
	}
	if err == nil {
		t.Fatal("expect verify error")
	}
}

// TestDecodeRSAPEM_Invalid checks decodeRSAPEM rejects invalid PEM input.
func TestDecodeRSAPEM_Invalid(t *testing.T) {
	if _, err := decodeRSAPEM([]byte("not pem")); err == nil {
		t.Fatal("expected error")
	}
}

// TestRSAKeyGenerator checks RSAKeyGenerator writes private.pem and public.pem in the working directory.
func TestRSAKeyGenerator(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(wd) }()

	ResetRsaKeyType(PublicKeyPKCS1, PrivateKeyPKCS1)
	if err := RSAKeyGenerator(1024); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("private.pem"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("public.pem"); err != nil {
		t.Fatal(err)
	}
}
