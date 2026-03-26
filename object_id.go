/**
 * @Author: lidonglin
 * @Description:
 * @File:  object_id.go
 * @Version: 1.0.0
 * @Date: 2022/11/05 11:21
 */

package tutil

import (
	"bytes"
	"database/sql/driver"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Oid is a 12-byte MongoDB BSON ObjectID; convertible with primitive.ObjectID.
type Oid [12]byte

// ZeroOid is the all-zero ObjectID (nil / empty sentinel).
var ZeroOid = Oid(primitive.NilObjectID)

// NewOidHex returns a new ObjectID as a 24-char lowercase hex string.
func NewOidHex() string {
	return primitive.NewObjectID().Hex()
}

// NewOid returns a new random ObjectID.
func NewOid() Oid {
	return Oid(primitive.NewObjectID())
}

// NewOidFromTimestamp builds an ObjectID from t (timestamp in first 4 bytes, MongoDB semantics).
func NewOidFromTimestamp(time time.Time) Oid {
	return Oid(primitive.NewObjectIDFromTimestamp(time))
}

// NewOidHexFromTimestamp is like NewOidFromTimestamp but returns the hex string.
func NewOidHexFromTimestamp(time time.Time) string {
	return NewOidFromTimestamp(time).Hex()
}

// ParseOid parses a 24-character hex string into Oid. On error returns ZeroOid and a non-nil error.
func ParseOid(id string) (Oid, error) {
	if len(id) != 24 {
		return ZeroOid, fmt.Errorf("invalid oid string")
	}

	b, err := hex.DecodeString(id)
	if err != nil {
		return ZeroOid, err
	}

	if len(b) != 12 {
		return ZeroOid, fmt.Errorf("invalid oid hex string")
	}

	var i Oid
	copy(i[0:12], b[:])

	return i, nil
}

// ToOid wraps ParseOid and ignores errors (invalid input becomes ZeroOid). Prefer ParseOid when you need errors.
func ToOid(id string) Oid {
	i, _ := ParseOid(id)
	return i
}

// Timestamp returns the embedded Unix time (seconds, UTC) from the ObjectID.
func (o Oid) Timestamp() time.Time {
	unixSecs := binary.BigEndian.Uint32(o[0:4])

	return time.Unix(int64(unixSecs), 0).UTC()
}

// IsZero reports whether o equals ZeroOid.
func (o Oid) IsZero() bool {
	return bytes.Equal(o[:], ZeroOid[:])
}

// GormDataType implements schema.GormDataTypeInterface; returns "binary(12)".
func (o Oid) GormDataType() string {
	return "binary(12)"
}

// Value implements driver.Valuer (12 raw bytes for the DB driver).
func (o Oid) Value() (driver.Value, error) {
	return o[:], nil
}

// Scan implements sql.Scanner: nil maps to ZeroOid; v must be []byte of length 12.
func (o *Oid) Scan(v interface{}) error {
	if o == nil {
		return fmt.Errorf("failed to scan oid: nil receiver")
	}

	if v == nil {
		*o = ZeroOid

		return nil
	}

	oidBytes, ok := v.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan oid: want []byte, got %T", v)
	}

	if len(oidBytes) != 12 {
		return fmt.Errorf("failed to scan oid: want 12 bytes, got %d", len(oidBytes))
	}

	copy(o[:], oidBytes)

	return nil
}

// Hex returns the 24-character lowercase hex encoding of o.
func (o Oid) Hex() string {
	return hex.EncodeToString(o[:])
}

// String returns the same value as Hex.
func (o Oid) String() string {
	return o.Hex()
}
