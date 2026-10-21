package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/komari-monitor/komari/internal/config"
	logger "github.com/komari-monitor/komari/utils/log"
	"gorm.io/gorm"
)

// marketDownloadMaxBytes limits the response size of a market download.
const marketDownloadMaxBytes = 100 << 20

const marketDownloadTimeout = 45 * time.Second

// dangerouslyTargetedMarketPrefixes lists address ranges that are never a
// legitimate market source: loopback, link-local (including cloud metadata
// endpoints) and the unspecified address. They are rejected even when the
// administrator explicitly disables SSRF protection, because a mistyped or
// attacker-influenced URL there can never be intended. Private ranges
// (10/8, 172.16/12, 192.168/16) stay allowed: self-hosted intranet markets are
// a supported deployment.
var dangerouslyTargetedMarketPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),    // IPv4 loopback.
	netip.MustParsePrefix("169.254.0.0/16"), // IPv4 link-local, incl. 169.254.169.254 metadata.
	netip.MustParsePrefix("fe80::/10"),      // IPv6 link-local.
	netip.MustParsePrefix("0.0.0.0/32"),     // IPv4 unspecified.
	netip.MustParsePrefix("::/128"),         // IPv6 unspecified.
}

var blockedMarketIPPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // RFC 6598 shared address space.
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1.
	netip.MustParsePrefix("198.18.0.0/15"),   // Benchmarking.
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2.
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3.
	netip.MustParsePrefix("240.0.0.0/4"),     // Reserved, including broadcast.
	netip.MustParsePrefix("2001:db8::/32"),   // Documentation.
	netip.MustParsePrefix("fec0::/10"),       // Deprecated site-local unicast.
}

// protectedMarketDownloadTransport resolves a hostname once per connection,
// checks every result, and dials the validated IP directly. Proxies are
// disabled so the destination checked here is the destination actually used.
var protectedMarketDownloadTransport = newSSRFProtectedTransport()

// IsSSRFProtectionEnabled reports whether SSRF protection is enabled for
// market downloads. An unreadable setting is treated as enabled so callers
// using this status helper fail closed.
func IsSSRFProtectionEnabled() bool {
	enabled, err := ssrfProtectionEnabled()
	return err != nil || enabled
}

// DownloadMarketURL performs a market download. Loopback, link-local and
// unspecified targets are always rejected. When SSRF protection is enabled,
// URLs resolving to private or internal addresses are rejected as well
// (including on every redirect hop); when it is disabled, downloads to other
// addresses proceed without further filtering.
func DownloadMarketURL(rawURL string, maxSize int64) ([]byte, error) {
	if err := validateMarketDownloadTarget(rawURL); err != nil {
		return nil, err
	}
	protectionEnabled, err := ssrfProtectionEnabled()
	if err != nil {
		return nil, fmt.Errorf("unable to determine SSRF protection state: %w", err)
	}

	transport := http.DefaultTransport
	if protectionEnabled {
		transport = protectedMarketDownloadTransport
	}
	client := &http.Client{
		Timeout:   marketDownloadTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return validateMarketDownloadTarget(req.URL.String())
		},
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("response exceeds the %d byte limit", maxSize)
	}
	if len(data) == 0 {
		return nil, errors.New("empty response")
	}
	return data, nil
}

func validateMarketDownloadURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil {
		return errors.New("only HTTP and HTTPS URLs are allowed")
	}
	return nil
}

// validateMarketDownloadTarget applies the scheme/userinfo checks and then
// rejects targets that are obviously never a market source, even when SSRF
// protection has been switched off by the administrator.
func validateMarketDownloadTarget(rawURL string) error {
	if err := validateMarketDownloadURL(rawURL); err != nil {
		return err
	}
	return rejectDangerousMarketHost(rawURL)
}

// rejectDangerousMarketHost resolves the URL host and refuses loopback,
// link-local and unspecified addresses. Resolution failures fail closed.
func rejectDangerousMarketHost(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	host := parsed.Hostname()
	if host == "" {
		return errors.New("only HTTP and HTTPS URLs are allowed")
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve market download host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return errors.New("host did not resolve to an IP address")
	}
	for _, ip := range ips {
		if isDangerousMarketIP(ip) {
			return fmt.Errorf("market download host %q resolves to a loopback, link-local, or unspecified address", host)
		}
	}
	return nil
}

// isDangerousMarketIP reports whether ip is a loopback, link-local, or
// unspecified address. A nil (unparseable) address counts as dangerous.
func isDangerousMarketIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}

	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	address = address.Unmap()
	for _, prefix := range dangerouslyTargetedMarketPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func newSSRFProtectedTransport() *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{}
	}
	transport := base.Clone()
	transport.Proxy = nil
	transport.Dial = nil
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.DialContext = dialMarketAddress
	return transport
}

func dialMarketAddress(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid market download address %q: %w", address, err)
	}

	ips, err := resolveMarketIPs(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve market download host %q: %w", host, err)
	}
	for _, ip := range ips {
		if isBlockedMarketIP(ip) {
			return nil, errors.New("requests to private or internal addresses are not allowed")
		}
	}

	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, ip := range ips {
		if network == "tcp4" && ip.To4() == nil {
			continue
		}
		if network == "tcp6" && ip.To4() != nil {
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		return nil, fmt.Errorf("no compatible address found for market download host %q", host)
	}
	return nil, fmt.Errorf("failed to connect to market download host %q: %w", host, lastErr)
}

func resolveMarketIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		if address.IP != nil {
			ips = append(ips, address.IP)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("host did not resolve to an IP address")
	}
	return ips, nil
}

func isBlockedMarketIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return true
	}

	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	address = address.Unmap()
	for _, prefix := range blockedMarketIPPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func ssrfProtectionEnabled() (bool, error) {
	enabled, err := config.GetAs[bool](config.SSRFProtectionEnabledKey)
	if err == nil {
		return enabled, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		// Fail closed: an unreadable setting must not silently disable filtering.
		return false, err
	}
	// The key is absent (fresh install or an upgraded installation that predates
	// this option): enable protection and persist it so administrators can still
	// switch it off explicitly.
	if err := config.Set(config.SSRFProtectionEnabledKey, true); err != nil {
		return false, err
	}
	logger.Info("admin-api", "ssrf_protection_enabled was not configured; SSRF protection is now enabled by default for market downloads")
	return true, nil
}
