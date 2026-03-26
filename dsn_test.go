package tutil

import (
	"net/url"
	"strings"
	"testing"
)

// TestMysqlDsnEncode checks password escaping for a simple user:password@host DSN.
func TestMysqlDsnEncode(t *testing.T) {
	t.Parallel()
	raw := "user:p@ss/word@localhost"
	got := MysqlDsnEncode(raw)
	if !strings.Contains(got, "user:") || !strings.Contains(got, "@localhost") {
		t.Fatalf("unexpected layout: %s", got)
	}
	idx := strings.Index(got, "@localhost")
	if idx <= 0 {
		t.Fatal("missing @localhost")
	}
	encPassPart := got[len("user:"):idx]
	unescaped, err := url.QueryUnescape(encPassPart)
	if err != nil {
		t.Fatal(err)
	}
	if unescaped != "p@ss/word" {
		t.Fatalf("password mismatch: %q", unescaped)
	}
}
