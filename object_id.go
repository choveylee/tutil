package tutil

import (
	"bytes"
	"database/sql/driver"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Oid is a 12-byte MongoDB BSON ObjectID value.
// It corresponds to bson.ObjectID from the MongoDB Go driver.
type Oid [12]byte

// ZeroOid is the all-zero ObjectID used as a sentinel value.
// SQL NULL values scan as ZeroOid.
var ZeroOid = Oid(bson.NilObjectID)

// NewOidHex returns a newly generated ObjectID as a 24-character lowercase hexadecimal string,
// using the same encoding as bson.ObjectID.Hex.
func NewOidHex() string {
	return bson.NewObjectID().Hex()
}

// NewOidStr returns a newly generated ObjectID as a string using the same encoding as NewOidHex.
func NewOidStr() string {
	return Oid(bson.NewObjectID()).String()
}

// NewOid returns a newly generated ObjectID from the standard MongoDB ObjectID construction.
func NewOid() Oid {
	return Oid(bson.NewObjectID())
}

// NewOidFromTimestamp returns an ObjectID derived from timestamp using MongoDB layout:
// four big-endian seconds since the Unix epoch followed by random bytes.
func NewOidFromTimestamp(timestamp time.Time) Oid {
	return Oid(bson.NewObjectIDFromTimestamp(timestamp))
}

// NewOidHexFromTimestamp returns the hexadecimal string representation of NewOidFromTimestamp(timestamp).
func NewOidHexFromTimestamp(timestamp time.Time) string {
	return NewOidFromTimestamp(timestamp).Hex()
}

// ParseOid parses id, which must contain exactly 24 hexadecimal digits, into an Oid.
// On failure it returns ZeroOid and a non-nil error.
func ParseOid(id string) (Oid, error) {
	if len(id) != 24 {
		return ZeroOid, fmt.Errorf("oid: invalid hex length %d, want 24", len(id))
	}

	oidBytes, err := hex.DecodeString(id)
	if err != nil {
		return ZeroOid, fmt.Errorf("oid: invalid hexadecimal encoding: %w", err)
	}

	var oid Oid
	copy(oid[:], oidBytes)

	return oid, nil
}

// ToOid parses id using ParseOid and returns ZeroOid if parsing fails.
func ToOid(id string) Oid {
	oid, _ := ParseOid(id)

	return oid
}

// Timestamp returns the UTC time with second precision encoded in the first four bytes of o.
func (o Oid) Timestamp() time.Time {
	unixSecs := binary.BigEndian.Uint32(o[0:4])

	return time.Unix(int64(unixSecs), 0).UTC()
}

// IsZero reports whether o equals ZeroOid.
func (o Oid) IsZero() bool {
	return bytes.Equal(o[:], ZeroOid[:])
}

// GormDataType is used by GORM for schema typing and returns "binary(12)" for raw ObjectID storage.
func (o Oid) GormDataType() string {
	return "binary(12)"
}

// Value implements driver.Valuer by returning the 12-byte binary ObjectID representation.
func (o Oid) Value() (driver.Value, error) {
	return o[:], nil
}

// Scan implements sql.Scanner. A nil value maps to ZeroOid.
// Accepted types are []byte of length 12 or a 24-digit hexadecimal string.
func (o *Oid) Scan(val any) error {
	if o == nil {
		return fmt.Errorf("oid: scan on nil *Oid receiver")
	}

	if val == nil {
		*o = ZeroOid

		return nil
	}

	switch x := val.(type) {
	case []byte:
		if len(x) != 12 {
			return fmt.Errorf("oid: invalid []byte length %d, want 12", len(x))
		}

		copy(o[:], x)

		return nil
	case string:
		oid, err := ParseOid(x)
		if err != nil {
			return err
		}

		*o = oid

		return nil
	default:
		return fmt.Errorf("oid: invalid scan source type %T, want []byte or string", val)
	}
}

// Hex returns the canonical 24-character lowercase hexadecimal representation of o.
func (o Oid) Hex() string {
	return hex.EncodeToString(o[:])
}

// String returns the same value as Hex.
func (o Oid) String() string {
	return o.Hex()
}
