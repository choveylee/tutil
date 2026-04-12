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

// Oid is a 12-byte MongoDB ObjectID; interop with bson.ObjectID.
type Oid [12]byte

// ZeroOid is the all-zero sentinel; SQL NULL scans as ZeroOid.
var ZeroOid = Oid(bson.NilObjectID)

// NewOidHex returns a new ObjectID as 24-char lowercase hex (same as bson.ObjectID.Hex).
func NewOidHex() string {
	return bson.NewObjectID().Hex()
}

// NewOidStr returns a new ObjectID string (same 24-char lowercase hex as NewOidHex).
func NewOidStr() string {
	return Oid(bson.NewObjectID()).String()
}

// NewOid returns a new random ObjectID.
func NewOid() Oid {
	return Oid(bson.NewObjectID())
}

// NewOidFromTimestamp builds an ObjectID (4-byte big-endian Unix seconds per Mongo, then random bytes).
func NewOidFromTimestamp(timestamp time.Time) Oid {
	return Oid(bson.NewObjectIDFromTimestamp(timestamp))
}

// NewOidHexFromTimestamp is NewOidFromTimestamp but returns the hex string.
func NewOidHexFromTimestamp(timestamp time.Time) string {
	return NewOidFromTimestamp(timestamp).Hex()
}

// ParseOid parses 24-char hex (len 24, valid hex); on error returns (ZeroOid, err).
func ParseOid(id string) (Oid, error) {
	if len(id) != 24 {
		return ZeroOid, fmt.Errorf("invalid oid string")
	}

	oidBytes, err := hex.DecodeString(id)
	if err != nil {
		return ZeroOid, err
	}

	var oid Oid
	copy(oid[:], oidBytes)

	return oid, nil
}

// ToOid parses id via ParseOid and ignores errors (invalid id becomes ZeroOid).
func ToOid(id string) Oid {
	oid, _ := ParseOid(id)

	return oid
}

// Timestamp returns Unix seconds (UTC) from the first 4 bytes.
func (o Oid) Timestamp() time.Time {
	unixSecs := binary.BigEndian.Uint32(o[0:4])

	return time.Unix(int64(unixSecs), 0).UTC()
}

// IsZero reports whether o equals ZeroOid.
func (o Oid) IsZero() bool {
	return bytes.Equal(o[:], ZeroOid[:])
}

// GormDataType returns "binary(12)" for GORM migrations.
func (o Oid) GormDataType() string {
	return "binary(12)"
}

// Value returns the 12 raw bytes for driver.Valuer.
func (o Oid) Value() (driver.Value, error) {
	return o[:], nil
}

// Scan sets o from nil (ZeroOid), []byte len 12, or 24-char hex string; otherwise errors.
func (o *Oid) Scan(val any) error {
	if o == nil {
		return fmt.Errorf("failed to scan oid: nil receiver")
	}

	if val == nil {
		*o = ZeroOid

		return nil
	}

	switch x := val.(type) {
	case []byte:
		if len(x) != 12 {
			return fmt.Errorf("failed to scan oid: want 12 bytes, got %d", len(x))
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
		return fmt.Errorf("failed to scan oid: want []byte or string, got %T", val)
	}
}

// Hex returns 24-char lowercase hex.
func (o Oid) Hex() string {
	return hex.EncodeToString(o[:])
}

// String is the same as Hex.
func (o Oid) String() string {
	return o.Hex()
}
