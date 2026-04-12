/**
 * @Author: lidonglin
 * @Description: MySQL DSN helper: URL-escape password segment (limited string shapes).
 * @File:  dsn.go
 * @Version: 1.0.0
 * @Date: 2022/12/07 23:06
 */

package tutil

import (
	"net/url"
)

// MysqlDsnEncode URL-escapes the password substring between the first ':' and the last '@' in dsn.
//
// It only matches simple user:password@host-style strings; DSNs with a scheme (for example mysql://)
// or ':' inside the password can be parsed incorrectly—validate inputs before use.
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
