package security

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestParseTrustedProxies(t *testing.T) {
	tests := []struct {
		raw  string
		want []string
	}{
		{"", DefaultTrustedProxies},
		{"  ", DefaultTrustedProxies},
		{"none", nil},
		{"ALL", []string{"0.0.0.0/0", "::/0"}},
		{"*", []string{"0.0.0.0/0", "::/0"}},
		{"10.1.0.0/16, 203.0.113.7\n2001:db8::/32", []string{"10.1.0.0/16", "203.0.113.7", "2001:db8::/32"}},
	}
	for _, tt := range tests {
		if got := ParseTrustedProxies(tt.raw); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseTrustedProxies(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestDefaultTrustedProxiesOnlyCoverLoopback(t *testing.T) {
	want := []string{"127.0.0.0/8", "::1/128"}
	if !reflect.DeepEqual(DefaultTrustedProxies, want) {
		t.Fatalf("DefaultTrustedProxies = %v, want only loopback %v", DefaultTrustedProxies, want)
	}
}

func TestApplyTrustedProxiesRejectsInvalidEntries(t *testing.T) {
	if err := ApplyTrustedProxies(gin.New(), "not-an-ip"); err == nil {
		t.Fatal("expected an error for an invalid proxy entry")
	}
}

func TestApplyTrustedProxiesUsesSingleRemoteIPHeader(t *testing.T) {
	r := gin.New()
	if err := ApplyTrustedProxies(r, ""); err != nil {
		t.Fatalf("ApplyTrustedProxies: %v", err)
	}
	if want := []string{"X-Forwarded-For"}; !reflect.DeepEqual(r.RemoteIPHeaders, want) {
		t.Fatalf("RemoteIPHeaders = %v, want %v", r.RemoteIPHeaders, want)
	}
}

func TestApplyTrustedProxiesWithHeaderHonoursCustomHeader(t *testing.T) {
	r := gin.New()
	if err := ApplyTrustedProxiesWithHeader(r, "", "X-Real-IP"); err != nil {
		t.Fatalf("ApplyTrustedProxiesWithHeader: %v", err)
	}
	if want := []string{"X-Real-IP"}; !reflect.DeepEqual(r.RemoteIPHeaders, want) {
		t.Fatalf("RemoteIPHeaders = %v, want %v", r.RemoteIPHeaders, want)
	}
}

func clientIPFor(t *testing.T, raw, remoteAddr string) string {
	t.Helper()
	return clientIPForHeaders(t, raw, remoteAddr, map[string]string{"X-Forwarded-For": "198.51.100.9"})
}

func clientIPForHeaders(t *testing.T, raw, remoteAddr string, headers map[string]string) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if err := ApplyTrustedProxies(r, raw); err != nil {
		t.Fatalf("ApplyTrustedProxies: %v", err)
	}
	var got string
	r.GET("/", func(c *gin.Context) { got = c.ClientIP() })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	r.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestDefaultTrustedProxiesIgnoreForwardedHeadersFromPublicPeers(t *testing.T) {
	if got := clientIPFor(t, "", "203.0.113.5:4000"); got != "203.0.113.5" {
		t.Fatalf("ClientIP = %q, want the direct peer address", got)
	}
}

func TestDefaultTrustedProxiesIgnoreForwardedHeadersFromPrivatePeers(t *testing.T) {
	// Acceptance: with the default configuration a Docker bridge peer must not
	// be able to smuggle a client IP in via X-Forwarded-For.
	if got := clientIPFor(t, "", "172.17.0.1:4000"); got != "172.17.0.1" {
		t.Fatalf("ClientIP = %q, want the direct Docker bridge address", got)
	}
}

func TestDefaultTrustedProxiesHonourLocalReverseProxy(t *testing.T) {
	if got := clientIPFor(t, "", "127.0.0.1:4000"); got != "198.51.100.9" {
		t.Fatalf("ClientIP = %q, want the forwarded client address", got)
	}
}

func TestConfiguredTrustedProxiesHonourDockerBridge(t *testing.T) {
	// Acceptance: after --trusted-proxies 172.17.0.0/16 the forwarded address
	// from the Docker bridge is believed.
	if got := clientIPFor(t, "172.17.0.0/16", "172.17.0.1:4000"); got != "198.51.100.9" {
		t.Fatalf("ClientIP = %q, want the forwarded client address", got)
	}
}

func TestTrustedProxyIgnoresXRealIPWhenOnlyForwardedForEnabled(t *testing.T) {
	got := clientIPForHeaders(t, "", "127.0.0.1:4000", map[string]string{
		"X-Real-IP": "198.51.100.9",
	})
	if got != "127.0.0.1" {
		t.Fatalf("ClientIP = %q, want the direct peer because X-Real-IP must be ignored", got)
	}
}

func newTestWarner(raw string) (*ProxyTrustWarner, *[]string) {
	var messages []string
	w := newProxyTrustWarner(raw, func(message string) {
		messages = append(messages, message)
	})
	return w, &messages
}

func warnerRequest(remoteAddr, forwardedFor string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}
	return req
}

func TestProxyTrustWarnerWarnsForUntrustedPrivatePeer(t *testing.T) {
	w, messages := newTestWarner("")
	w.check(warnerRequest("172.17.0.1:4000", "198.51.100.9"))
	if len(*messages) != 1 {
		t.Fatalf("warnings = %d, want 1", len(*messages))
	}
	got := (*messages)[0]
	if !strings.Contains(got, "172.17.0.1") || !strings.Contains(got, "--trusted-proxies") {
		t.Fatalf("warning %q should name the peer and the --trusted-proxies flag", got)
	}
}

func TestProxyTrustWarnerStaysQuietForTrustedPrivatePeer(t *testing.T) {
	w, messages := newTestWarner("172.17.0.0/16")
	w.check(warnerRequest("172.17.0.1:4000", "198.51.100.9"))
	if len(*messages) != 0 {
		t.Fatalf("warnings = %d, want 0 for a trusted peer", len(*messages))
	}
}

func TestProxyTrustWarnerStaysQuietForPublicPeer(t *testing.T) {
	w, messages := newTestWarner("")
	w.check(warnerRequest("203.0.113.5:4000", "198.51.100.9"))
	if len(*messages) != 0 {
		t.Fatalf("warnings = %d, want 0 for a public peer", len(*messages))
	}
}

func TestProxyTrustWarnerIgnoresMissingForwardedHeader(t *testing.T) {
	w, messages := newTestWarner("")
	w.check(warnerRequest("172.17.0.1:4000", ""))
	if len(*messages) != 0 {
		t.Fatalf("warnings = %d, want 0 without X-Forwarded-For", len(*messages))
	}
}

func TestProxyTrustWarnerThrottlesToOncePerHour(t *testing.T) {
	w, messages := newTestWarner("")

	w.check(warnerRequest("172.17.0.1:4000", "198.51.100.9"))
	if len(*messages) != 1 {
		t.Fatalf("warnings = %d, want 1 after first request", len(*messages))
	}

	// Immediately repeating the same condition must not warn again.
	w.check(warnerRequest("172.17.0.2:4000", "198.51.100.9"))
	if len(*messages) != 1 {
		t.Fatalf("warnings = %d, want still 1 within the throttle window", len(*messages))
	}

	// Pretend the last warning happened just over an hour ago.
	w.lastWarn.Store(time.Now().Add(-proxyWarningInterval - time.Second).Unix())
	w.check(warnerRequest("172.17.0.3:4000", "198.51.100.9"))
	if len(*messages) != 2 {
		t.Fatalf("warnings = %d, want 2 after the throttle window elapsed", len(*messages))
	}
}
