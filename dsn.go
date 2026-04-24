package tutil

import (
	"net/url"
)

// MysqlDsnEncode applies URL query escaping to the password field in a simple MySQL DSN.
// The password is interpreted as the substring between the first ':' and the last '@'.
//
// The implementation assumes a user:password@host layout. Connection strings with URL schemes,
// empty passwords, or driver-specific userinfo forms should be parsed and escaped by callers.
func MysqlDsnEncode(dsn string) string {
	var password string
	var i, j int

	for i = len(dsn) - 1; i >= 0; i-- {
		if dsn[i] == '@' {
			for j = 0; j < i; j++ {
				if dsn[j] == ':' {
					password = dsn[j+1 : i]
					break
				}
			}
			break
		}
	}

	if password != "" {
		dsn = dsn[0:j+1] + url.QueryEscape(password) + dsn[i:]
	}

	return dsn
}
