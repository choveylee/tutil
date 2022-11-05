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

type Oid [12]byte

var ZeroOid = Oid(primitive.NilObjectID)

func NewOidHex() string {
	return primitive.NewObjectID().Hex()
}

func NewOid() Oid {
	return Oid(primitive.NewObjectID())
}

func NewOidFromTimestamp(time time.Time) Oid {
	return Oid(primitive.NewObjectIDFromTimestamp(time))
}

func NewOidHexFromTimestamp(time time.Time) string {
	return NewOidFromTimestamp(time).Hex()
}

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

func ToOid(id string) Oid {
	i, _ := ParseOid(id)
	return i
}

// Timestamp extracts the time part of the Oid.
func (o Oid) Timestamp() time.Time {
	unixSecs := binary.BigEndian.Uint32(o[0:4])

	return time.Unix(int64(unixSecs), 0).UTC()
}

func (o Oid) IsZero() bool {
	return bytes.Equal(o[:], ZeroOid[:])
}

// GormDataType return gorm.io/gorm data type, implement schema.GormDataTypeInterface interface
func (o Oid) GormDataType() string {
	return "binary(12)"
}

// Value return hex value, implement driver.Valuer interface
func (o Oid) Value() (driver.Value, error) {
	return o[:], nil
}

// Scan implements the sql.Scanner interface
func (o Oid) Scan(v interface{}) error {
	bs, ok := v.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan oid: %v", v)
	}

	copy(o[0:12], bs[:])

	return nil
}

func (o Oid) Hex() string {
	return hex.EncodeToString(o[:])
}

func (o Oid) String() string {
	return o.Hex()
}
