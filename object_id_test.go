package tutil

import (
	"encoding/hex"
	"testing"
)

// TestParseOid covers invalid input and a valid 24-char hex round-trip.
func TestParseOid(t *testing.T) {
	t.Parallel()
	_, err := ParseOid("short")
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = ParseOid("zzzzzzzzzzzzzzzzzzzzzzzz")
	if err == nil {
		t.Fatal("expected hex decode error")
	}
	hex24 := "507f1f77bcf86cd799439011"
	oid, err := ParseOid(hex24)
	if err != nil {
		t.Fatal(err)
	}
	if oid.Hex() != hex24 {
		t.Fatalf("round hex: %s", oid.Hex())
	}
}

// TestToOid_InvalidSilent ensures ToOid ignores parse errors without panicking.
func TestToOid_InvalidSilent(t *testing.T) {
	t.Parallel()
	_ = ToOid("nope")
}

// TestOid_Scan_Value tests driver Valuer, Scan from []byte, SQL NULL, and short input.
func TestOid_Scan_Value(t *testing.T) {
	t.Parallel()
	id, err := ParseOid("507f1f77bcf86cd799439011")
	if err != nil {
		t.Fatal(err)
	}
	v, err := id.Value()
	if err != nil {
		t.Fatal(err)
	}
	bs, ok := v.([]byte)
	if !ok || len(bs) != 12 {
		t.Fatalf("Value: %T len=%d", v, len(bs))
	}

	var o Oid
	if err := o.Scan(bs); err != nil {
		t.Fatal(err)
	}
	if o != id {
		t.Fatal("scan mismatch")
	}

	var z Oid
	if err := z.Scan(nil); err != nil {
		t.Fatal(err)
	}
	if !z.IsZero() {
		t.Fatal("nil -> zero")
	}

	if err := (&Oid{}).Scan([]byte{1, 2, 3}); err == nil {
		t.Fatal("short slice should error")
	}
}

// TestOid_Timestamp_Hex_String checks Hex, String, and Timestamp on a new OID.
func TestOid_Timestamp_Hex_String(t *testing.T) {
	t.Parallel()
	oid := NewOid()
	h := oid.Hex()
	if len(h) != 24 {
		t.Fatalf("hex len %d", len(h))
	}
	dec, err := hex.DecodeString(h)
	if err != nil || len(dec) != 12 {
		t.Fatal(err)
	}
	if oid.String() != h {
		t.Fatal("String != Hex")
	}
	_ = oid.Timestamp()
}
