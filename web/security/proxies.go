package security

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// DefaultTrustedProxies covers reverse proxies on the same host or on a
// private network (Docker bridge, LAN). X-Forwarded-For / X-Real-IP sent by
// any other peer are ignored, so clients cannot forge the address used for
// audit logs and login rate limiting.
var DefaultTrustedProxies = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
}

// ParseTrustedProxies converts the --trusted-proxies value into the list
// handed to gin. An empty value keeps DefaultTrustedProxies, "none" trusts no
// proxy, and "*" or "all" restores the legacy behaviour of trusting every
// peer. Anything else is a comma or whitespace separated list of IPs/CIDRs.
func ParseTrustedProxies(raw string) []string {
	entries := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if len(entries) == 0 {
		return append([]string(nil), DefaultTrustedProxies...)
	}
	if len(entries) == 1 {
		switch strings.ToLower(entries[0]) {
		case "none":
			return nil
		case "*", "all":
			return []string{"0.0.0.0/0", "::/0"}
		}
	}
	return entries
}

// ApplyTrustedProxies configures which peers may supply the client IP.
func ApplyTrustedProxies(r *gin.Engine, raw string) error {
	return r.SetTrustedProxies(ParseTrustedProxies(raw))
}
