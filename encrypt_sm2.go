/**
 * @Author: lidonglin
 * @Description:
 * @File:  encrypt_sm2.go
 * @Version: 1.0.0
 * @Date: 2024/8/24 13:18:31
 */

package tutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

func Sm2Decrypt(cipherText string, hexPrivateKey string) ([]byte, error) {
	privateKey, err := x509.ReadPrivateKeyFromHex(hexPrivateKey)
	if err != nil {
		return nil, err
	}

	cipher2Text, err := hex.DecodeString("04" + cipherText)
	if err != nil {
		return nil, err
	}

	if len(cipher2Text) < 33 {
		return nil, fmt.Errorf("cipher lens")
	}

	plainText, err := sm2.Decrypt(privateKey, cipher2Text, sm2.C1C3C2)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func Sm2Encrypt(ctx context.Context, plainText []byte, hexPublicKey string) ([]byte, error) {
	publicKey, err := x509.ReadPublicKeyFromHex(hexPublicKey)
	if err != nil {
		return nil, err
	}

	cipherText, err := sm2.Encrypt(publicKey, plainText, rand.Reader, sm2.C1C3C2)
	if err != nil {
		return nil, err
	}

	return cipherText, nil
}

func GenSm2KeyPair(ctx context.Context) (string, string, error) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	hexPrivateKey := x509.WritePrivateKeyToHex(privateKey)
	hexPublicKey := x509.WritePublicKeyToHex(&privateKey.PublicKey)

	return hexPrivateKey, hexPublicKey, nil
}
