package tutil

import (
	"bytes"
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// Uid is a 16-byte ULID (Universally Unique Lexicographically Sortable Identifier).
// The canonical text encoding is the 26-character Crockford Base32 string returned by String.
type Uid [16]byte

// ZeroUid is the all-zero ULID used as a sentinel value.
// SQL NULL values scan as ZeroUid.
var ZeroUid = Uid(ulid.Zero)

// NewUidStr returns a newly generated ULID as a 26-character Crockford Base32 string.
// It is equivalent to calling NewUid followed by String.
func NewUidStr() string {
	return ulid.Make().String()
}

// NewUid returns a newly generated ULID using the current UTC time and default entropy, as defined by ulid.Make.
func NewUid() Uid {
	return Uid(ulid.Make())
}

// NewUidFromTimestamp constructs a ULID from timestamp interpreted in UTC with millisecond precision,
// using ulid.DefaultEntropy as the random source.
// On failure (for example, timestamp outside the representable ULID range) it returns ZeroUid and a non-nil error.
func NewUidFromTimestamp(timestamp time.Time) (Uid, error) {
	milliSeconds := ulid.Timestamp(timestamp.UTC())

	id, err := ulid.New(milliSeconds, ulid.DefaultEntropy())
	if err != nil {
		return ZeroUid, err
	}

	return Uid(id), nil
}

// NewUidStrFromTimestamp returns the string representation from NewUidFromTimestamp.
// On failure it returns an empty string and a non-nil error.
func NewUidStrFromTimestamp(timestamp time.Time) (string, error) {
	u, err := NewUidFromTimestamp(timestamp)
	if err != nil {
		return "", err
	}

	return u.String(), nil
}

// ParseUid parses id as a 26-character ULID string using ulid.ParseStrict.
// On failure it returns ZeroUid and a non-nil error.
func ParseUid(id string) (Uid, error) {
	uid, err := ulid.ParseStrict(id)
	if err != nil {
		return ZeroUid, err
	}

	return Uid(uid), nil
}

// ToUid parses id using ParseUid and returns ZeroUid if parsing fails.
func ToUid(id string) Uid {
	uid, _ := ParseUid(id)

	return uid
}

// Timestamp returns the UTC time with millisecond precision encoded in u.
func (u Uid) Timestamp() time.Time {
	return ulid.ULID(u).Timestamp()
}

// IsZero reports whether u equals ZeroUid.
func (u Uid) IsZero() bool {
	return bytes.Equal(u[:], ZeroUid[:])
}

// GormDataType is used by GORM for schema typing and returns "binary(16)" for raw ULID storage.
func (u Uid) GormDataType() string {
	return "binary(16)"
}

// Value implements driver.Valuer by returning the 16-byte binary ULID representation.
func (u Uid) Value() (driver.Value, error) {
	return u[:], nil
}

// Scan implements sql.Scanner. A nil value maps to ZeroUid.
// Accepted types are []byte of length 16 or a 26-character ULID string.
func (u *Uid) Scan(val any) error {
	if u == nil {
		return fmt.Errorf("uid: scan on nil *Uid receiver")
	}

	if val == nil {
		*u = ZeroUid

		return nil
	}

	switch x := val.(type) {
	case []byte:
		if len(x) != 16 {
			return fmt.Errorf("uid: invalid []byte length %d, want 16", len(x))
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
		return fmt.Errorf("uid: invalid scan source type %T, want []byte or string", val)
	}
}

// String returns the canonical 26-character Crockford Base32 representation of u.
func (u Uid) String() string {
	return ulid.ULID(u).String()
}
