# tutil

[![Go Reference](https://pkg.go.dev/badge/github.com/choveylee/tutil.svg)](https://pkg.go.dev/github.com/choveylee/tutil)

General-purpose helpers for Go: **ULIDs**, **MongoDB ObjectIDs**, hashing and HMAC, **AES** / **RSA** / **SM2** / **SM4**, non-cryptographic random values, and MySQL DSN password escaping.

## Installation

```bash
go get github.com/choveylee/tutil
```

Requires **Go 1.25** or later (see [`go.mod`](go.mod)).

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

- **Identifiers** — `Uid` (ULID) and `Oid` (12-byte BSON ObjectID); `database/sql` scanning and `driver.Valuer`; GORM column types via `GormDataType`.
- **Hashing** — MD5, SHA-1, HMAC variants (legacy algorithms documented as such).
- **Symmetric crypto** — AES and SM4 ECB/CBC with PKCS#7 or zero padding.
- **Asymmetric crypto** — RSA (PEM encrypt/decrypt, SHA-256 sign/verify); SM2 encrypt/decrypt via [`gmsm`](https://pkg.go.dev/github.com/tjfoc/gmsm).
- **Randomness** — `math/rand`-based integers and strings; **not** for secrets or tokens.
- **MySQL** — `MysqlDsnEncode` URL-escapes the password in simple `user:password@host` DSNs (validate inputs; complex DSN shapes are not handled).

### Direct dependencies

| Module | Role |
|--------|------|
| [`github.com/oklog/ulid/v2`](https://pkg.go.dev/github.com/oklog/ulid/v2) | ULID generation and parsing |
| [`go.mongodb.org/mongo-driver/v2/bson`](https://pkg.go.dev/go.mongodb.org/mongo-driver/v2/bson) | ObjectID backing type |
| [`github.com/tjfoc/gmsm`](https://pkg.go.dev/github.com/tjfoc/gmsm) | SM2 / SM4 |

## Security

For new work, prefer authenticated encryption (e.g. AES-GCM) instead of raw ECB/CBC helpers. MD5, SHA-1, and `math/rand` helpers are for compatibility or non-security use only—see per-symbol documentation for IV rules, padding, and errors.

## Contributing

Issues and pull requests are welcome. Run:

```bash
go test ./...
go vet ./...
```

before submitting changes.
