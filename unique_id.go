/**
 * @Author: lidonglin
 * @Description: ULID type, constructors, sql.Scanner, GORM binary(16).
 * @File:  unique_id.go
 * @Version: 1.0.0
 * @Date: 2026/02/11 00:00
 */

// Package tutil provides helpers for lexicographic IDs (ULID, MongoDB ObjectID), hashing and
// symmetric/asymmetric crypto (AES, RSA, SM2, SM4), non-cryptographic random strings and integers,
// and MySQL DSN password escaping.
package tutil

import (
	"bytes"
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// Uid is a 16-byte ULID (Universally Unique Lexicographically Sortable Identifier).
// The canonical text form is the 26-character Crockford Base32 string from String.
type Uid [16]byte

// ZeroUid is the all-zero ULID used as a sentinel; database NULL scans as ZeroUid.
var ZeroUid = Uid(ulid.Zero)

// NewUidStr returns a new ULID as a 26-character Crockford Base32 string (equivalent to NewUid().String()).
func NewUidStr() string {
	return ulid.Make().String()
}

// NewUid returns a new ULID using the current UTC time and default entropy (same as ulid.Make).
func NewUid() Uid {
	return Uid(ulid.Make())
}

// NewUidFromTimestamp returns a ULID from timestamp in UTC with millisecond precision, using ulid.DefaultEntropy.
// On failure (for example timestamp out of ULID range) it returns ZeroUid and a non-nil error.
func NewUidFromTimestamp(timestamp time.Time) (Uid, error) {
	milliSeconds := ulid.Timestamp(timestamp.UTC())

	id, err := ulid.New(milliSeconds, ulid.DefaultEntropy())
	if err != nil {
		return ZeroUid, err
	}

	return Uid(id), nil
}

// NewUidStrFromTimestamp returns the Base32 string from NewUidFromTimestamp, or ("", err) on failure.
func NewUidStrFromTimestamp(timestamp time.Time) (string, error) {
	u, err := NewUidFromTimestamp(timestamp)
	if err != nil {
		return "", err
	}

	return u.String(), nil
}

// ParseUid parses id as a 26-character ULID using ulid.ParseStrict.
// On error it returns ZeroUid and a non-nil error.
func ParseUid(id string) (Uid, error) {
	uid, err := ulid.ParseStrict(id)
	if err != nil {
		return ZeroUid, err
	}

	return Uid(uid), nil
}

// ToUid wraps ParseUid and returns ZeroUid when parsing fails.
func ToUid(id string) Uid {
	uid, _ := ParseUid(id)

	return uid
}

// Timestamp returns the UTC time embedded in u with millisecond precision.
func (u Uid) Timestamp() time.Time {
	return ulid.ULID(u).Timestamp()
}

// IsZero reports whether u is equal to ZeroUid.
func (u Uid) IsZero() bool {
	return bytes.Equal(u[:], ZeroUid[:])
}

// GormDataType implements GORM schema typing and returns "binary(16)" for raw ULID storage.
func (u Uid) GormDataType() string {
	return "binary(16)"
}

// Value implements driver.Valuer and returns the 16 raw ULID bytes.
func (u Uid) Value() (driver.Value, error) {
	return u[:], nil
}

// Scan implements sql.Scanner. nil maps to ZeroUid; []byte of length 16 (raw) or a 26-character ULID string are accepted.
func (u *Uid) Scan(val any) error {
	if u == nil {
		return fmt.Errorf("failed to scan uid: nil receiver")
	}

	if val == nil {
		*u = ZeroUid

		return nil
	}

	switch x := val.(type) {
	case []byte:
		if len(x) != 16 {
			return fmt.Errorf("failed to scan uid: want 16 bytes, got %d", len(x))
		}

		copy(u[:], x)

		return nil
	case string:
		uid, err := ParseUid(x)
		if err != nil {
			return err
		}

		*u = uid

		return nil
	default:
		return fmt.Errorf("failed to scan uid: want []byte or string, got %T", val)
	}
}

// String returns the canonical 26-character Crockford Base32 encoding of u.
func (u Uid) String() string {
	return ulid.ULID(u).String()
}
