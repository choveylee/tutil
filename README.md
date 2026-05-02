# tutil

[![Go Reference](https://pkg.go.dev/badge/github.com/choveylee/tutil.svg)](https://pkg.go.dev/github.com/choveylee/tutil)

tutil is a compact Go utility package for sortable identifiers, hashing and
HMAC helpers, interoperability-oriented AES/RSA/SM2/SM4 helpers,
non-cryptographic random values, and MySQL DSN password escaping.

## Installation

```bash
go get github.com/choveylee/tutil
```

Requires **Go 1.25** or later.

## Quick start

```go
package main

import (
	"fmt"

	"github.com/choveylee/tutil"
)

func main() {
	u := tutil.NewUid()
	fmt.Println(u.String())

	oid := tutil.NewOid()
	fmt.Println(oid.Hex())
}
```

Complete API reference: [pkg.go.dev/github.com/choveylee/tutil](https://pkg.go.dev/github.com/choveylee/tutil).

## Features

- **Identifiers** - `Uid` (ULID) and `Oid` (12-byte BSON ObjectID), including `database/sql` scanning, `driver.Valuer`, string parsing, and GORM schema type hints.
- **Hashing and HMAC** - MD5, SHA-1, HMAC-MD5, HMAC-SHA1, and HMAC-SHA256 helpers. MD5 and SHA-1 are retained for compatibility scenarios.
- **Symmetric cryptography** - AES and SM4 ECB/CBC helpers with PKCS #7 or zero padding for interoperability with existing systems.
- **Asymmetric cryptography** - RSA PEM key generation, RSAES-OAEP encryption/decryption, and SHA-256 signing/verification, plus SM2 encryption/decryption via [`gmsm`](https://pkg.go.dev/github.com/tjfoc/gmsm).
- **Random values** - `math/rand`-based integers and strings intended only for non-security use.
- **MySQL DSN escaping** - `MysqlDsnEncode` escapes the password portion of simple `user:password@host` DSNs.

### Direct dependencies

| Module | Role |
|--------|------|
| [`github.com/oklog/ulid/v2`](https://pkg.go.dev/github.com/oklog/ulid/v2) | ULID generation and parsing |
| [`go.mongodb.org/mongo-driver/v2/bson`](https://pkg.go.dev/go.mongodb.org/mongo-driver/v2/bson) | ObjectID backing type |
| [`github.com/tjfoc/gmsm`](https://pkg.go.dev/github.com/tjfoc/gmsm) | SM2 / SM4 |

## API Notes

- `AesEncrypt` and `AesDecrypt` operate on exactly one AES block. Use the explicit ECB/CBC helpers for longer inputs.
- AES-CBC uses the first key block as the IV when `iv` is empty. This behavior is retained for legacy compatibility; new code should supply a fresh random IV.
- Zero padding is lossy when plaintext can end with zero bytes.
- `RsaEncrypt` and `RsaDecrypt` use RSAES-OAEP with SHA-256.
- `ResetRsaKeyType` configures the process-wide default PEM encodings used by `RSAKeyGenerator` and `RSAKeyGeneratorTo`. RSA parsing helpers detect key formats from the PEM block type.
- `RSAKeyGeneratorTo` accepts 1024-bit keys for legacy interoperability; new deployments should use at least 2048 bits.
- `MysqlDsnEncode` is intentionally narrow in scope. Use a DSN parser for URL-style or driver-specific connection strings.

## Security

For new designs, prefer authenticated encryption such as AES-GCM over raw
ECB/CBC helpers. MD5, SHA-1, RSASSA-PKCS1-v1_5 signatures, 1024-bit RSA keys,
and `math/rand` helpers are retained for compatibility or non-security use
cases.

## Contributing

Issues and pull requests are welcome. Before submitting changes, run:

```bash
go test ./...
go vet ./...
```
