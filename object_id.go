/**
 * @Author: lidonglin
 * @Description: BSON ObjectID type, constructors, sql.Scanner, GORM binary(12).
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

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Oid is a 12-byte MongoDB BSON ObjectID; it converts to and from bson.ObjectID.
type Oid [12]byte

// ZeroOid is the all-zero ObjectID sentinel; database NULL scans as ZeroOid.
var ZeroOid = Oid(bson.NilObjectID)

// NewOidHex returns a new ObjectID as a 24-character lowercase hexadecimal string (same as bson.ObjectID.Hex).
func NewOidHex() string {
	return bson.NewObjectID().Hex()
}

// NewOidStr returns a new ObjectID as a string (same encoding as NewOidHex).
func NewOidStr() string {
	return Oid(bson.NewObjectID()).String()
}

// NewOid returns a new cryptographically random ObjectID.
func NewOid() Oid {
	return Oid(bson.NewObjectID())
}

// NewOidFromTimestamp returns an ObjectID with MongoDB layout: 4-byte big-endian Unix seconds then random bytes.
func NewOidFromTimestamp(timestamp time.Time) Oid {
	return Oid(bson.NewObjectIDFromTimestamp(timestamp))
}

// NewOidHexFromTimestamp returns the hexadecimal string form of NewOidFromTimestamp(timestamp).
func NewOidHexFromTimestamp(timestamp time.Time) string {
	return NewOidFromTimestamp(timestamp).Hex()
}

// ParseOid parses id as 24 hexadecimal digits into Oid.
// On error it returns ZeroOid and a non-nil error.
func ParseOid(id string) (Oid, error) {
	if len(id) != 24 {
		return ZeroOid, fmt.Errorf("oid: expected 24 hexadecimal characters, got length %d", len(id))
	}

	oidBytes, err := hex.DecodeString(id)
	if err != nil {
		return ZeroOid, fmt.Errorf("oid: invalid hexadecimal encoding: %w", err)
	}

	var oid Oid
	copy(oid[:], oidBytes)

	return oid, nil
}

// ToOid wraps ParseOid and returns ZeroOid when parsing fails.
func ToOid(id string) Oid {
	oid, _ := ParseOid(id)

	return oid
}

// Timestamp returns the Unix time in seconds (UTC) stored in the first four bytes of o.
func (o Oid) Timestamp() time.Time {
	unixSecs := binary.BigEndian.Uint32(o[0:4])

	return time.Unix(int64(unixSecs), 0).UTC()
}

// IsZero reports whether o is equal to ZeroOid.
func (o Oid) IsZero() bool {
	return bytes.Equal(o[:], ZeroOid[:])
}

// GormDataType implements GORM schema typing and returns "binary(12)" for raw ObjectID storage.
func (o Oid) GormDataType() string {
	return "binary(12)"
}

// Value implements driver.Valuer and returns the 12 raw ObjectID bytes.
func (o Oid) Value() (driver.Value, error) {
	return o[:], nil
}

// Scan implements sql.Scanner. nil maps to ZeroOid; []byte of length 12 or a 24-digit hex string are accepted.
func (o *Oid) Scan(val any) error {
	if o == nil {
		return fmt.Errorf("oid: Scan on nil *Oid receiver")
	}

	if val == nil {
		*o = ZeroOid

		return nil
	}

	switch x := val.(type) {
	case []byte:
		if len(x) != 12 {
			return fmt.Errorf("oid: []byte length is %d; expected 12", len(x))
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
		return fmt.Errorf("oid: unsupported source type %T; expected []byte or string", val)
	}
}

// Hex returns the 24-character lowercase hexadecimal encoding of o.
func (o Oid) Hex() string {
	return hex.EncodeToString(o[:])
}

// String returns the same lowercase hexadecimal form as Hex.
func (o Oid) String() string {
	return o.Hex()
}
