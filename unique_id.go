/**
 * @Author: lidonglin
 * @Description: ULID type, constructors, sql.Scanner, GORM binary(16).
 * @File:  unique_id.go
 * @Version: 1.0.0
 * @Date: 2026/02/11 00:00
 */

package tutil

import (
	"bytes"
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// Uid is a 16-byte ULID; use raw bytes or String for the canonical 26-char Base32 form.
type Uid [16]byte

// ZeroUid is the all-zero sentinel; SQL NULL scans as ZeroUid.
var ZeroUid = Uid(ulid.Zero)

// NewUidStr returns a new ULID as a 26-char Crockford Base32 string (same as NewUid().String()).
func NewUidStr() string {
	return ulid.Make().String()
}

// NewUid returns a new ULID (UTC time + default entropy, same as ulid.Make).
func NewUid() Uid {
	return Uid(ulid.Make())
}

// NewUidFromTimestamp builds a ULID from timestamp (UTC ms) with ulid.DefaultEntropy; on failure returns (ZeroUid, err).
func NewUidFromTimestamp(timestamp time.Time) (Uid, error) {
	milliSeconds := ulid.Timestamp(timestamp.UTC())

	id, err := ulid.New(milliSeconds, ulid.DefaultEntropy())
	if err != nil {
		return ZeroUid, err
	}

	return Uid(id), nil
}

// NewUidStrFromTimestamp is NewUidFromTimestamp but returns the Base32 string ("", err on failure).
func NewUidStrFromTimestamp(timestamp time.Time) (string, error) {
	u, err := NewUidFromTimestamp(timestamp)
	if err != nil {
		return "", err
	}

	return u.String(), nil
}

// ParseUid parses a 26-char ULID with ulid.ParseStrict; on error returns (ZeroUid, err).
func ParseUid(id string) (Uid, error) {
	uid, err := ulid.ParseStrict(id)
	if err != nil {
		return ZeroUid, err
	}

	return Uid(uid), nil
}

// ToUid parses id via ParseUid and ignores errors (invalid id becomes ZeroUid).
func ToUid(id string) Uid {
	uid, _ := ParseUid(id)

	return uid
}

// Timestamp returns the embedded UTC time (millisecond precision).
func (u Uid) Timestamp() time.Time {
	return ulid.ULID(u).Timestamp()
}

// IsZero reports whether u equals ZeroUid.
func (u Uid) IsZero() bool {
	return bytes.Equal(u[:], ZeroUid[:])
}

// GormDataType returns "binary(16)" for GORM migrations.
func (u Uid) GormDataType() string {
	return "binary(16)"
}

// Value returns the 16 raw bytes for driver.Valuer.
func (u Uid) Value() (driver.Value, error) {
	return u[:], nil
}

// Scan sets u from nil (ZeroUid), []byte len 16, or 26-char ULID string; otherwise errors.
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

// String returns the canonical 26-char Crockford Base32 ULID.
func (u Uid) String() string {
	return ulid.ULID(u).String()
}
