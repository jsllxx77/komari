package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/pkg/rpc"
)

func newCSRFTestEngine(principal *rpc.Principal) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if principal != nil {
			SetPrincipal(c, principal)
		}
		c.Next()
	}, CSRFProtection())
	r.Any("/mutate", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func doCSRF(t *testing.T, r *gin.Engine, method, path string, headers map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestCSRFProtectionAllowsSafeMethods(t *testing.T) {
	r := newCSRFTestEngine(nil)
	if code := doCSRF(t, r, http.MethodGet, "/mutate", map[string]string{"Origin": "https://evil.example"}); code != http.StatusOK {
		t.Fatalf("GET should not be filtered, got %d", code)
	}
}

func TestCSRFProtectionRejectsCrossSiteOrigin(t *testing.T) {
	r := newCSRFTestEngine(nil)
	code := doCSRF(t, r, http.MethodPost, "/mutate", map[string]string{"Origin": "https://evil.example"})
	if code != http.StatusForbidden {
		t.Fatalf("cross-site POST should be 403, got %d", code)
	}
}

func TestCSRFProtectionAllowsSameOrigin(t *testing.T) {
	r := newCSRFTestEngine(nil)
	req := httptest.NewRequest(http.MethodPost, "/mutate", nil)
	req.Host = "panel.example"
	req.Header.Set("Origin", "https://panel.example")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("same-origin POST should pass, got %d", w.Code)
	}
}

func TestCSRFProtectionUsesSecFetchSite(t *testing.T) {
	r := newCSRFTestEngine(nil)
	if code := doCSRF(t, r, http.MethodPost, "/mutate", map[string]string{"Sec-Fetch-Site": "cross-site"}); code != http.StatusForbidden {
		t.Fatalf("Sec-Fetch-Site: cross-site should be 403, got %d", code)
	}
	for _, site := range []string{"same-origin", "none", ""} {
		if code := doCSRF(t, r, http.MethodPost, "/mutate", map[string]string{"Sec-Fetch-Site": site}); code != http.StatusOK {
			t.Fatalf("Sec-Fetch-Site %q should pass, got %d", site, code)
		}
	}
}

func TestCSRFProtectionSkipsTokenPrincipals(t *testing.T) {
	for _, p := range []*rpc.Principal{rpc.NewAPIKeyPrincipal(), rpc.NewAgentPrincipal("11111111-1111-1111-1111-111111111111")} {
		r := newCSRFTestEngine(p)
		code := doCSRF(t, r, http.MethodPost, "/mutate", map[string]string{"Origin": "https://evil.example"})
		if code != http.StatusOK {
			t.Fatalf("token principal should bypass CSRF, got %d", code)
		}
	}
}

func TestIsSameOriginMutationAllowlist(t *testing.T) {
	req := func(origin string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/mutate", nil)
		r.Host = "panel.example"
		r.Header.Set("Origin", origin)
		return r
	}
	if !isSameOriginMutation(req("https://console.example"), "https://console.example") {
		t.Fatal("exact allowlist entry should be accepted")
	}
	if isSameOriginMutation(req("https://console.example"), "*") {
		t.Fatal("wildcard allowlist entry must not accept credentialed writes")
	}
	if !isSameOriginMutation(req("https://console.example"), "*,https://console.example") {
		t.Fatal("exact entry alongside wildcard should be accepted")
	}
	if isSameOriginMutation(req("https://evil.example"), "https://console.example") {
		t.Fatal("unlisted origin should be rejected")
	}
}

func TestLegacyStateChangingGetRejectsCrossSiteNavigation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/legacy", LegacyStateChangingGet(), func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/legacy", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site GET should be 403, got %d", w.Code)
	}

	for _, site := range []string{"same-origin", "none", ""} {
		req := httptest.NewRequest(http.MethodGet, "/legacy", nil)
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Sec-Fetch-Site %q should pass, got %d", site, w.Code)
		}
	}
}
