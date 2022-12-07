/**
 * @Author: lidonglin
 * @Description:
 * @File:  dsn.go
 * @Version: 1.0.0
 * @Date: 2022/12/07 23:06
 */

package tutil

import (
	"net/url"
)

func DsnEncode(dsn string) string {
	password := ""
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
