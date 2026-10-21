package security

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	logger "github.com/komari-monitor/komari/utils/log"
)

// DefaultTrustedProxies only trusts the loopback interface. Reverse proxies
// that reach the app from a private/Docker network must be listed explicitly
// with --trusted-proxies (KOMARI_TRUSTED_PROXIES), for example:
//
//	--trusted-proxies 172.17.0.0/16            # default Docker bridge
//	--trusted-proxies 172.16.0.0/12,10.0.0.0/8 # other Docker/LAN ranges
//
// Trusting the whole private space by default is unsafe: with docker-proxy,
// Docker Desktop, rootless port forwarding or Kubernetes SNAT the peer address
// is a trusted internal address, so any client-supplied X-Forwarded-For would
// be believed and audit logs / login rate limiting could be forged.
var DefaultTrustedProxies = []string{
	"127.0.0.0/8",
	"::1/128",
}

// DefaultRemoteIPHeader is the only header gin is allowed to read the client
// IP from. Keeping a single header avoids the ambiguity of X-Forwarded-For and
// X-Real-IP being honoured at the same time.
const DefaultRemoteIPHeader = "X-Forwarded-For"

// proxyWarningInterval throttles the startup self-check warning so a
// misconfigured deployment logs at most one hint per hour.
const proxyWarningInterval = time.Hour

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

// ApplyTrustedProxies configures which peers may supply the client IP. Only
// DefaultRemoteIPHeader is consulted; see ApplyTrustedProxiesWithHeader to use
// a different single header such as X-Real-IP.
func ApplyTrustedProxies(r *gin.Engine, raw string) error {
	return ApplyTrustedProxiesWithHeader(r, raw, DefaultRemoteIPHeader)
}

// ApplyTrustedProxiesWithHeader is ApplyTrustedProxies with a configurable
// single remote-IP header. An empty header falls back to
// DefaultRemoteIPHeader.
func ApplyTrustedProxiesWithHeader(r *gin.Engine, raw, header string) error {
	if header == "" {
		header = DefaultRemoteIPHeader
	}
	r.RemoteIPHeaders = []string{header}
	return r.SetTrustedProxies(ParseTrustedProxies(raw))
}

// ProxyTrustWarner implements the startup self-check: the first time a request
// arrives from a private address that is not in the trusted-proxy list while
// carrying X-Forwarded-For, it logs a one-line hint that --trusted-proxies may
// need configuring. Warnings are throttled to at most one per hour.
type ProxyTrustWarner struct {
	prefixes []netip.Prefix
	lastWarn atomic.Int64 // unix seconds of the last warning, 0 if none
	warn     func(string)
}

// NewProxyTrustWarner builds a warner for the effective --trusted-proxies
// value. Invalid entries are ignored here because ApplyTrustedProxies already
// rejects them at startup.
func NewProxyTrustWarner(raw string) *ProxyTrustWarner {
	return newProxyTrustWarner(raw, func(message string) {
		logger.Warnf("security", "%s", message)
	})
}

func newProxyTrustWarner(raw string, warn func(string)) *ProxyTrustWarner {
	w := &ProxyTrustWarner{warn: warn}
	for _, entry := range ParseTrustedProxies(raw) {
		if prefix, err := parseTrustedProxyEntry(entry); err == nil {
			w.prefixes = append(w.prefixes, prefix)
		}
	}
	return w
}

func parseTrustedProxyEntry(entry string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		return prefix, nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()), nil
}

// trusts reports whether addr is covered by the configured trusted proxies.
func (w *ProxyTrustWarner) trusts(addr netip.Addr) bool {
	for _, prefix := range w.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Middleware checks every request. It is cheap and only reads headers, so it
// can run ahead of the application handlers.
func (w *ProxyTrustWarner) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		w.check(c.Request)
		c.Next()
	}
}

func (w *ProxyTrustWarner) check(r *http.Request) {
	if w == nil || r == nil {
		return
	}
	if r.Header.Get(DefaultRemoteIPHeader) == "" {
		return
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	addr = addr.Unmap()
	if !addr.IsPrivate() || w.trusts(addr) {
		return
	}
	w.warnAtMostHourly(addr)
}

func (w *ProxyTrustWarner) warnAtMostHourly(addr netip.Addr) {
	now := time.Now().Unix()
	for {
		last := w.lastWarn.Load()
		if last != 0 && now-last < int64(proxyWarningInterval/time.Second) {
			return
		}
		if w.lastWarn.CompareAndSwap(last, now) {
			break
		}
	}
	if w.warn != nil {
		w.warn("Request from private address " + addr.String() +
			" is not listed in --trusted-proxies but carries X-Forwarded-For; " +
			"if this peer is a reverse proxy, add its CIDR to --trusted-proxies " +
			"(e.g. 172.17.0.0/16 for the default Docker bridge)")
	}
}
