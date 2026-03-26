# tutil

[English](#english) · [中文](#中文)

---

<a id="english"></a>

## English

### Overview

**tutil** is a small Go utility library: hashing and HMAC, AES/SM4 block ciphers (ECB/CBC with PKCS#7 or zero padding), RSA PEM-based encrypt/sign, SM2 encrypt/decrypt, MongoDB-style `ObjectID` helpers, random string/integer helpers, and MySQL DSN password encoding.

Requires **Go 1.26.1** (see `go.mod`).

### Installation

```bash
go get github.com/choveylee/tutil
```

### Dependencies

| Module | Usage |
|--------|--------|
| [`go.mongodb.org/mongo-driver`](https://pkg.go.dev/go.mongodb.org/mongo-driver/bson/primitive) | `Oid` backed by `primitive.ObjectID` |
| [`github.com/tjfoc/gmsm`](https://pkg.go.dev/github.com/tjfoc/gmsm) | SM2 / SM4 |

### Modules (quick reference)

| Area | Symbols (examples) |
|------|-------------------|
| **Hash / MAC** | `Md5`, `Sha1`, `HmacSha1`, `HmacSha256`, `HmacMd5` |
| **AES** | `GetAes128Key`, `AesEncrypt` / `DecryptAES` (16-byte block ECB-style), PKCS#7 / zero padding helpers, `AesEcb*` / `AesCbc*` for ECB/CBC |
| **SM4** | `Sm4Ecb*` / `Sm4Cbc*` (PKCS#7 or zero padding), 16-byte key and IV |
| **SM2** | `GenSm2KeyPair`, `Sm2Encrypt`, `Sm2Decrypt` (hex keys) |
| **RSA** | `ResetRsaKeyType`, `RSAKeyGenerator`, `RsaEncrypt` / `RsaDecrypt`, `RsaSignature` / `RsaSignatureVerify` |
| **ObjectID** | `Oid`, `ZeroOid`, `NewOid`, `NewOidHex`, `ParseOid`, `ToOid`, `Scan` / `Value` for `database/sql` |
| **Random** | `RandInt`, `RandBaseInt`, `RandFloat32`, `RandCharStr`, `RandNumStr`, `RandSourceStr` |
| **MySQL DSN** | `MysqlDsnEncode` |

Integer/string random helpers use the global **`math/rand`** source (not `crypto/rand`).

### Security notes

- **MD5 / SHA-1** and **HMAC-MD5** are legacy; avoid for new security designs.
- **AES-ECB** and **SM4-ECB** do not use an IV; they are weak for structured data—prefer **CBC** (or modern modes) with a proper random IV and authenticated encryption when possible.
- **AES-CBC** helpers may accept a **nil IV** for backward compatibility (fixed zero IV in implementation); treat this as **legacy / unsafe** for new code.
- Review godoc on each symbol for length checks, padding rules, and error conditions.

### Tests

```bash
go test ./...
```

---

<a id="中文"></a>

## 中文

### 概述

**tutil** 是一个轻量 Go 工具库，提供：哈希与 HMAC、AES/SM4 分组加密（ECB/CBC，PKCS#7 或零填充补码）、基于 PEM 的 RSA 加解密与签名、SM2 加解密、MongoDB 风格 `ObjectID` 工具、随机字符串/整数辅助函数，以及 MySQL DSN 密码编码。

需要 **Go 1.26.1**（见 `go.mod`）。

### 安装

```bash
go get github.com/choveylee/tutil
```

### 依赖说明

| 模块 | 用途 |
|------|------|
| [`go.mongodb.org/mongo-driver`](https://pkg.go.dev/go.mongodb.org/mongo-driver/bson/primitive) | `Oid` 基于 `primitive.ObjectID` |
| [`github.com/tjfoc/gmsm`](https://pkg.go.dev/github.com/tjfoc/gmsm) | 国密 SM2 / SM4 |

### 功能一览

| 领域 | 主要 API（示例） |
|------|------------------|
| **哈希 / MAC** | `Md5`、`Sha1`、`HmacSha1`、`HmacSha256`、`HmacMd5` |
| **AES** | `GetAes128Key`、`AesEncrypt` / `DecryptAES`（16 字节分组、类 ECB）、PKCS#7 / 零填充、`AesEcb*` / `AesCbc*` |
| **SM4** | `Sm4Ecb*` / `Sm4Cbc*`（PKCS#7 或零填充），16 字节密钥与 IV |
| **SM2** | `GenSm2KeyPair`、`Sm2Encrypt`、`Sm2Decrypt`（十六进制密钥） |
| **RSA** | `ResetRsaKeyType`、`RSAKeyGenerator`、`RsaEncrypt` / `RsaDecrypt`、`RsaSignature` / `RsaSignatureVerify` |
| **ObjectID** | `Oid`、`ZeroOid`、`NewOid`、`NewOidHex`、`ParseOid`、`ToOid`，以及 `database/sql` 的 `Scan` / `Value` |
| **随机** | `RandInt`、`RandBaseInt`、`RandFloat32`、`RandCharStr`、`RandNumStr`、`RandSourceStr` |
| **MySQL DSN** | `MysqlDsnEncode` |

整数与字符串随机数使用全局 **`math/rand`** 源（非 `crypto/rand`）。

### 安全提示

- **MD5 / SHA-1**、**HMAC-MD5** 属遗留算法，新系统请勿用于安全设计。
- **AES-ECB**、**SM4-ECB** 无 IV，对结构化数据风险高——新代码优先 **CBC**（或更现代的模式）、随机 IV，并在需要时采用带认证的加密。
- **AES-CBC** 辅助函数可为兼容旧行为接受 **nil IV**（实现上为零 IV），新代码应视为 **不安全遗留**。
- 具体长度、填充与错误语义以各符号的 godoc 为准。

### 测试

```bash
go test ./...
```
