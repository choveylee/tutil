# tutil

[![Go Reference](https://pkg.go.dev/badge/github.com/choveylee/tutil.svg)](https://pkg.go.dev/github.com/choveylee/tutil)

Small Go utility package for sortable identifiers, hashing/HMAC helpers, AES/RSA/SM2/SM4 interoperability, non-cryptographic random values, and simple MySQL DSN password escaping.

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

Full API: [pkg.go.dev/github.com/choveylee/tutil](https://pkg.go.dev/github.com/choveylee/tutil).

## Features

- **Identifiers** - `Uid` (ULID) and `Oid` (12-byte BSON ObjectID), including `database/sql` scanning, `driver.Valuer`, string parsing, and GORM data type hints.
- **Hashing and HMAC** - MD5, SHA-1, HMAC-MD5, HMAC-SHA1, and HMAC-SHA256 helpers. MD5 and SHA-1 are retained for compatibility use cases.
- **Symmetric cryptography** - AES and SM4 ECB/CBC helpers with PKCS #7 or zero padding for interoperability with existing systems.
- **Asymmetric cryptography** - RSA PEM key generation, encryption/decryption, and SHA-256 signing/verification; SM2 encryption/decryption via [`gmsm`](https://pkg.go.dev/github.com/tjfoc/gmsm).
- **Random values** - `math/rand`-based integers and strings for non-security use only.
- **MySQL DSN escaping** - `MysqlDsnEncode` escapes the password portion of simple `user:password@host` DSNs.

### Direct dependencies

| Module | Role |
|--------|------|
| [`github.com/oklog/ulid/v2`](https://pkg.go.dev/github.com/oklog/ulid/v2) | ULID generation and parsing |
| [`go.mongodb.org/mongo-driver/v2/bson`](https://pkg.go.dev/go.mongodb.org/mongo-driver/v2/bson) | ObjectID backing type |
| [`github.com/tjfoc/gmsm`](https://pkg.go.dev/github.com/tjfoc/gmsm) | SM2 / SM4 |

## API Notes

- `AesEncrypt` and `AesDecrypt` operate on exactly one AES block. Use the explicit ECB/CBC helpers when working with longer inputs.
- AES-CBC uses the first key block as the IV when `iv` is empty. This is legacy behavior for compatibility; new code should pass a fresh random IV.
- Zero padding is lossy when plaintext can end with zero bytes.
- `ResetRsaKeyType` configures the process-wide default PEM formats used by RSA helpers. Invalid format values are rejected.
- `MysqlDsnEncode` is intentionally narrow: callers should use a DSN parser for URL-style or driver-specific connection strings.

## Security

For new designs, prefer authenticated encryption such as AES-GCM over raw ECB/CBC helpers. RSA PKCS #1 v1.5 encryption, MD5, SHA-1, and `math/rand` helpers are provided for compatibility or non-security use cases.

## Contributing

Issues and pull requests are welcome. Run:

```bash
go test ./...
go vet ./...
```

before submitting changes.
