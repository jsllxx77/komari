package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/internal/config"
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
	r.POST("/api/rpc2", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.POST("/api/login", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.POST("/api/oauth/2fa", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func cookieUser() *rpc.Principal {
	return rpc.NewUserPrincipal("11111111-1111-1111-1111-111111111111")
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

func withCORSAllowlist(t *testing.T, value string) {
	t.Helper()
	old, _ := config.GetAs[string](config.CorsAllowedOriginsKey, "")
	if err := config.Set(config.CorsAllowedOriginsKey, value); err != nil {
		t.Fatalf("set cors allowlist: %v", err)
	}
	t.Cleanup(func() { _ = config.Set(config.CorsAllowedOriginsKey, old) })
}

func TestCSRFProtectionAllowsSafeMethods(t *testing.T) {
	r := newCSRFTestEngine(cookieUser())
	if code := doCSRF(t, r, http.MethodGet, "/mutate", map[string]string{"Origin": "https://evil.example"}); code != http.StatusOK {
		t.Fatalf("GET should not be filtered, got %d", code)
	}
}

func TestCSRFProtectionRejectsCrossSiteOriginForCookieUser(t *testing.T) {
	r := newCSRFTestEngine(cookieUser())
	if code := doCSRF(t, r, http.MethodPost, "/mutate", map[string]string{"Origin": "https://evil.example"}); code != http.StatusForbidden {
		t.Fatalf("cross-origin POST from a cookie user should be 403, got %d", code)
	}
	if code := doCSRF(t, r, http.MethodPost, "/mutate", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}); code != http.StatusForbidden {
		t.Fatalf("Sec-Fetch-Site: cross-site POST from a cookie user should be 403, got %d", code)
	}
}

// 带着 session_token cookie 的请求即使会话已失效（身份是匿名）也按 cookie 会话检查。
func TestCSRFProtectionChecksRequestsCarryingSessionCookie(t *testing.T) {
	r := newCSRFTestEngine(rpc.NewAnonymousPrincipal())
	req := httptest.NewRequest(http.MethodPost, "/mutate", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "whatever"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST carrying a session cookie should be 403, got %d", w.Code)
	}
}

// CORS 配成 "*" 时，第三方页面匿名调用 /api/rpc2 不应被 CSRF 中间件拦截（F-23）。
func TestCSRFProtectionSkipsAnonymousRequests(t *testing.T) {
	withCORSAllowlist(t, "*")
	for _, p := range []*rpc.Principal{nil, rpc.NewAnonymousPrincipal()} {
		r := newCSRFTestEngine(p)
		headers := map[string]string{"Origin": "https://third-party.example", "Sec-Fetch-Site": "cross-site"}
		if code := doCSRF(t, r, http.MethodPost, "/api/rpc2", headers); code == http.StatusForbidden {
			t.Fatalf("anonymous cross-origin POST /api/rpc2 must not be 403")
		}
	}
}

// 反代没有透传 Host 时，浏览器给出的 Sec-Fetch-Site: same-origin 足以放行。
func TestCSRFProtectionTrustsSecFetchSiteSameOrigin(t *testing.T) {
	r := newCSRFTestEngine(cookieUser())
	req := httptest.NewRequest(http.MethodPost, "/mutate", nil)
	req.Host = "127.0.0.1:25774"
	req.Header.Set("Origin", "https://panel.example")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("same-origin POST behind a Host-rewriting proxy should pass, got %d", w.Code)
	}
}

func TestCSRFProtectionAllowsSameOriginWithoutSecFetchSite(t *testing.T) {
	r := newCSRFTestEngine(cookieUser())
	req := httptest.NewRequest(http.MethodPost, "/mutate", nil)
	req.Host = "panel.example"
	req.Header.Set("Origin", "https://panel.example")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("same-origin POST should pass, got %d", w.Code)
	}
}

// 没有 Sec-Fetch-Site 时，受信代理传来的 X-Forwarded-Host 可以代替被改写的 Host；
// 非受信对端的 X-Forwarded-Host 不采信。
func TestCSRFProtectionForwardedHostFromTrustedProxyOnly(t *testing.T) {
	r := newCSRFTestEngine(cookieUser())
	send := func(remoteAddr string) int {
		req := httptest.NewRequest(http.MethodPost, "/mutate", nil)
		req.RemoteAddr = remoteAddr
		req.Host = "127.0.0.1:25774"
		req.Header.Set("Origin", "https://panel.example")
		req.Header.Set("X-Forwarded-Host", "panel.example")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	if code := send("127.0.0.1:50000"); code != http.StatusOK {
		t.Fatalf("X-Forwarded-Host from a loopback proxy should be honoured, got %d", code)
	}
	if code := send("203.0.113.9:50000"); code != http.StatusForbidden {
		t.Fatalf("X-Forwarded-Host from an untrusted peer must be ignored, got %d", code)
	}
}

func TestCSRFProtectionUsesSecFetchSite(t *testing.T) {
	r := newCSRFTestEngine(cookieUser())
	if code := doCSRF(t, r, http.MethodPost, "/mutate", map[string]string{"Sec-Fetch-Site": "cross-site"}); code != http.StatusForbidden {
		t.Fatalf("Sec-Fetch-Site: cross-site should be 403, got %d", code)
	}
	for _, site := range []string{"same-origin", "none", ""} {
		if code := doCSRF(t, r, http.MethodPost, "/mutate", map[string]string{"Sec-Fetch-Site": site}); code != http.StatusOK {
			t.Fatalf("Sec-Fetch-Site %q should pass, got %d", site, code)
		}
	}
}

func TestCSRFProtectionSameSiteNeedsAllowlistedOrigin(t *testing.T) {
	withCORSAllowlist(t, "*,https://console.panel.example")
	r := newCSRFTestEngine(cookieUser())
	if code := doCSRF(t, r, http.MethodPost, "/mutate", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://console.panel.example"}); code != http.StatusOK {
		t.Fatalf("same-site POST from an allowlisted origin should pass, got %d", code)
	}
	if code := doCSRF(t, r, http.MethodPost, "/mutate", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://evil.panel.example"}); code != http.StatusForbidden {
		t.Fatalf("same-site POST from an unlisted origin (wildcard only) should be 403, got %d", code)
	}
}

func TestCSRFProtectionSkipsTokenPrincipals(t *testing.T) {
	for _, p := range []*rpc.Principal{rpc.NewAPIKeyPrincipal(), rpc.NewAgentPrincipal("11111111-1111-1111-1111-111111111111")} {
		r := newCSRFTestEngine(p)
		code := doCSRF(t, r, http.MethodPost, "/mutate", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
		if code != http.StatusOK {
			t.Fatalf("token principal should bypass CSRF, got %d", code)
		}
	}
}

// 登录 CSRF：匿名的跨站登录提交被拒绝，同源或无头的照常放行。
func TestCSRFProtectionRejectsCrossSiteLogin(t *testing.T) {
	r := newCSRFTestEngine(rpc.NewAnonymousPrincipal())
	for _, path := range []string{"/api/login", "/api/oauth/2fa"} {
		if code := doCSRF(t, r, http.MethodPost, path, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}); code != http.StatusForbidden {
			t.Fatalf("cross-site POST %s should be 403, got %d", path, code)
		}
		if code := doCSRF(t, r, http.MethodPost, path, map[string]string{"Sec-Fetch-Site": "same-origin"}); code != http.StatusOK {
			t.Fatalf("same-origin POST %s should pass, got %d", path, code)
		}
		if code := doCSRF(t, r, http.MethodPost, path, nil); code != http.StatusOK {
			t.Fatalf("POST %s without fetch metadata should pass, got %d", path, code)
		}
	}
}

func TestIsSameOriginMutationAllowlist(t *testing.T) {
	req := func(origin string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/mutate", nil)
		r.Host = "panel.example"
		r.RemoteAddr = "203.0.113.9:1234"
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
