/**
 * @Author: lidonglin
 * @Description:
 * @File:  encrypt_rsa.go
 * @Version: 1.0.0
 * @Date: 2023/10/31 16:01
 */

package tutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
)

const (
	PublicKeyPKIX = iota
	PublicKeyPKCS1
)

const (
	PrivateKeyPKCS1 = iota
	PrivateKeyPKCS8
)

var rsaPublicKeyType = PublicKeyPKCS1
var rsaPrivateKeyType = PrivateKeyPKCS1

func ResetRsaKeyType(publicKeyType int, privateKeyType int) {
	rsaPublicKeyType = publicKeyType
	rsaPrivateKeyType = privateKeyType
}

func RSAKeyGenerator(bits int) error {
	//GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	//Reader是一个全局、共享的密码用强随机数生成器
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	//保存私钥
	//通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	var X509PrivateKey []byte

	if rsaPrivateKeyType == PrivateKeyPKCS1 {
		X509PrivateKey = x509.MarshalPKCS1PrivateKey(privateKey)
	} else {
		X509PrivateKey, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return err
		}
	}

	//使用pem格式对x509输出的内容进行编码
	//创建文件保存私钥
	privateFile, err := os.Create("private.pem")
	if err != nil {
		return err
	}

	defer privateFile.Close()
	//构建一个pem.Block结构体对象
	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}

	//将数据保存到文件
	err = pem.Encode(privateFile, &privateBlock)
	if err != nil {
		return err
	}

	//保存公钥
	//获取公钥的数据
	publicKey := privateKey.PublicKey
	//X509对公钥编码

	var X509PublicKey []byte

	if rsaPublicKeyType == PublicKeyPKIX {
		X509PublicKey, err = x509.MarshalPKIXPublicKey(&publicKey)
		if err != nil {
			return err
		}
	} else {
		X509PublicKey = x509.MarshalPKCS1PublicKey(&publicKey)
	}

	//pem格式编码
	//创建用于保存公钥的文件
	publicFile, err := os.Create("public.pem")
	if err != nil {
		return err
	}

	defer publicFile.Close()

	//创建一个pem.Block结构体对象
	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}

	//保存到文件
	err = pem.Encode(publicFile, &publicBlock)
	if err != nil {
		return err
	}

	return nil
}

func RsaEncrypt(plainText, key []byte) ([]byte, error) {
	//pem解码
	block, _ := pem.Decode(key)

	var publicKey *rsa.PublicKey

	var err error

	if rsaPublicKeyType == PublicKeyPKIX {
		//x509解码
		publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		publicKey = publicKeyInterface.(*rsa.PublicKey)
	} else {
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	//对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		return nil, err
	}

	return cipherText, nil
}

func RsaDecrypt(cipherText, key []byte) ([]byte, error) {
	//pem解码
	block, _ := pem.Decode(key)

	var privateKey *rsa.PrivateKey

	var err error

	//X509解码
	if rsaPrivateKeyType == PrivateKeyPKCS1 {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	} else {
		privateInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		privateKey = privateInterface.(*rsa.PrivateKey)
	}

	//对密文进行解密
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func RsaSignature(keyType int, cipherText, key []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(key))

	var privateKey *rsa.PrivateKey

	var err error

	if rsaPrivateKeyType == PrivateKeyPKCS1 {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	} else {
		privateInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		privateKey = privateInterface.(*rsa.PrivateKey)
	}

	// sha256 加密方式，必须与 下面的 crypto.SHA256 对应
	hash := sha256.New()
	hash.Write(cipherText)

	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash.Sum(nil))

	return sign, err
}

func RsaSignatureVerify(cipherText, sign, key []byte) (bool, error) {
	block, _ := pem.Decode(key)

	var publicKey *rsa.PublicKey

	var err error

	if rsaPublicKeyType == PublicKeyPKIX {
		//x509解码
		publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return false, err
		}

		//类型断言
		publicKey = publicKeyInterface.(*rsa.PublicKey)
	} else {
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return false, err
		}
	}

	// sha256 加密方式，必须与 下面的 crypto.SHA256 对应
	hash := sha256.New()
	hash.Write(cipherText)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash.Sum(nil), sign)
	if err != nil {
		return false, nil
	}

	return true, nil
}
