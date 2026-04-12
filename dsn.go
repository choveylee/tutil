package tutil

import (
	"net/url"
)

// MysqlDsnEncode applies URL query escaping to the password field in dsn, defined as the substring
// between the first ':' and the last '@'.
//
// The implementation assumes a simple user:password@host layout. Connection strings that include a
// scheme (for example mysql://) or a colon inside the password may be handled incorrectly; callers
// must validate inputs when those forms are possible.
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
