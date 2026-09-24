package security

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

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

func TestApplyTrustedProxiesRejectsInvalidEntries(t *testing.T) {
	if err := ApplyTrustedProxies(gin.New(), "not-an-ip"); err == nil {
		t.Fatal("expected an error for an invalid proxy entry")
	}
}

func clientIPFor(t *testing.T, raw, remoteAddr string) string {
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
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	r.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestDefaultTrustedProxiesIgnoreForwardedHeadersFromPublicPeers(t *testing.T) {
	if got := clientIPFor(t, "", "203.0.113.5:4000"); got != "203.0.113.5" {
		t.Fatalf("ClientIP = %q, want the direct peer address", got)
	}
}

func TestDefaultTrustedProxiesHonourLocalReverseProxy(t *testing.T) {
	if got := clientIPFor(t, "", "127.0.0.1:4000"); got != "198.51.100.9" {
		t.Fatalf("ClientIP = %q, want the forwarded client address", got)
	}
}
