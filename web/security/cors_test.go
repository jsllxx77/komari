package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/internal/config"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestCorsMiddlewareValidatesAPIOrigins(t *testing.T) {
	setupCORSConfigDB(t, "")
	router := setupCORSRouter(true, "https://allowed.example")

	tests := []struct {
		name            string
		origin          string
		wantStatus      int
		wantAllowOrigin string
	}{
		{
			name:       "allows API requests without Origin",
			wantStatus: http.StatusOK,
		},
		{
			name:            "allows same host Origin",
			origin:          "https://api.example",
			wantStatus:      http.StatusOK,
			wantAllowOrigin: "https://api.example",
		},
		{
			name:            "allows configured Origin",
			origin:          "https://allowed.example",
			wantStatus:      http.StatusOK,
			wantAllowOrigin: "https://allowed.example",
		},
		{
			name:       "rejects unlisted Origin",
			origin:     "https://evil.example",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := performCORSRequest(router, http.MethodGet, "/api/ping", "api.example", tt.origin)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}
			if got := response.Header().Get("Access-Control-Allow-Origin"); got != tt.wantAllowOrigin {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, tt.wantAllowOrigin)
			}
		})
	}
}

func TestCorsMiddlewareAllowsAPIKeyRequestsFromAnyOrigin(t *testing.T) {
	setupCORSConfigDB(t, "123456789012")
	router := setupCORSRouter(true, "")

	request := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	request.Host = "api.example"
	request.Header.Set("Origin", "https://evil.example")
	request.Header.Set("Authorization", "Bearer 123456789012")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "https://evil.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, "https://evil.example")
	}
}

func TestCorsMiddlewareHandlesAPIPreflight(t *testing.T) {
	setupCORSConfigDB(t, "")
	router := setupCORSRouter(true, "https://allowed.example")

	allowed := performCORSRequest(router, http.MethodOptions, "/api/ping", "api.example", "https://allowed.example")
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("allowed preflight status = %d, want %d", allowed.Code, http.StatusNoContent)
	}
	if got := allowed.Header().Get("Access-Control-Allow-Origin"); got != "https://allowed.example" {
		t.Fatalf("allowed preflight Access-Control-Allow-Origin = %q", got)
	}

	rejected := performCORSRequest(router, http.MethodOptions, "/api/ping", "api.example", "https://evil.example")
	if rejected.Code != http.StatusForbidden {
		t.Fatalf("rejected preflight status = %d, want %d", rejected.Code, http.StatusForbidden)
	}
}

func TestCorsMiddlewareAllowsAuthorizationPreflightFromAnyOrigin(t *testing.T) {
	setupCORSConfigDB(t, "")
	router := setupCORSRouter(true, "")

	request := httptest.NewRequest(http.MethodOptions, "/api/ping", nil)
	request.Host = "api.example"
	request.Header.Set("Origin", "https://evil.example")
	request.Header.Set("Access-Control-Request-Headers", "authorization")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "https://evil.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, "https://evil.example")
	}
	if got := response.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want empty", got)
	}
}

func TestCorsMiddlewareDisabledSkipsAPIValidation(t *testing.T) {
	setupCORSConfigDB(t, "")
	router := setupCORSRouter(false, "")

	response := performCORSRequest(router, http.MethodGet, "/api/ping", "api.example", "https://evil.example")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want empty", got)
	}
}

func TestCorsMiddlewareSkipsNonAPIPaths(t *testing.T) {
	setupCORSConfigDB(t, "")
	router := setupCORSRouter(true, "")

	response := performCORSRequest(router, http.MethodGet, "/public", "api.example", "https://evil.example")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want empty", got)
	}
}

func TestCorsMiddlewareWildcardAllowlistOmitsCredentials(t *testing.T) {
	setupCORSConfigDB(t, "")
	router := setupCORSRouter(true, "*")

	response := performCORSRequest(router, http.MethodGet, "/api/ping", "api.example", "https://evil.example")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "https://evil.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want the echoed Origin", got)
	}
	if got := response.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want empty for a wildcard allowlist", got)
	}
	if got := response.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q, want %q", got, "Origin")
	}

	preflight := performCORSRequest(router, http.MethodOptions, "/api/ping", "api.example", "https://evil.example")
	if preflight.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want %d", preflight.Code, http.StatusNoContent)
	}
	if got := preflight.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("preflight Access-Control-Allow-Credentials = %q, want empty for a wildcard allowlist", got)
	}
}

func TestCorsMiddlewareExactAllowlistKeepsCredentials(t *testing.T) {
	setupCORSConfigDB(t, "")
	router := setupCORSRouter(true, "https://allowed.example")

	response := performCORSRequest(router, http.MethodGet, "/api/ping", "api.example", "https://allowed.example")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "https://allowed.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := response.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want %q for an exact allowlist match", got, "true")
	}
	if got := response.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q, want %q", got, "Origin")
	}

	sameHost := performCORSRequest(router, http.MethodGet, "/api/ping", "api.example", "https://api.example")
	if got := sameHost.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("same-host Access-Control-Allow-Credentials = %q, want %q", got, "true")
	}
}

func TestCorsMiddlewareWildcardWithExplicitEntryKeepsCredentialsForThatEntry(t *testing.T) {
	setupCORSConfigDB(t, "")
	router := setupCORSRouter(true, "*,https://allowed.example")

	explicit := performCORSRequest(router, http.MethodGet, "/api/ping", "api.example", "https://allowed.example")
	if got := explicit.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("explicitly listed Origin Access-Control-Allow-Credentials = %q, want %q", got, "true")
	}

	wildcard := performCORSRequest(router, http.MethodGet, "/api/ping", "api.example", "https://other.example")
	if got := wildcard.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("wildcard-only Origin Access-Control-Allow-Credentials = %q, want empty", got)
	}
}

func TestOriginInAllowlistReportsWildcard(t *testing.T) {
	tests := []struct {
		name         string
		allowlist    string
		origin       string
		wantMatched  bool
		wantWildcard bool
	}{
		{name: "wildcard", allowlist: "*", origin: "https://any.example", wantMatched: true, wantWildcard: true},
		{name: "wildcard among entries", allowlist: "https://allowed.example,*", origin: "https://any.example", wantMatched: true, wantWildcard: true},
		{name: "exact entry wins over leading wildcard", allowlist: "*,https://allowed.example", origin: "https://allowed.example", wantMatched: true},
		{name: "exact origin", allowlist: "https://allowed.example", origin: "https://allowed.example", wantMatched: true},
		{name: "exact host", allowlist: "allowed.example", origin: "http://allowed.example", wantMatched: true},
		{name: "no match", allowlist: "https://allowed.example", origin: "https://evil.example"},
		{name: "invalid origin", allowlist: "*", origin: "not-a-url"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, viaWildcard := OriginInAllowlist(tt.origin, tt.allowlist)
			if matched != tt.wantMatched {
				t.Fatalf("OriginInAllowlist(%q, %q) matched = %v, want %v", tt.origin, tt.allowlist, matched, tt.wantMatched)
			}
			if viaWildcard != tt.wantWildcard {
				t.Fatalf("OriginInAllowlist(%q, %q) viaWildcard = %v, want %v", tt.origin, tt.allowlist, viaWildcard, tt.wantWildcard)
			}
		})
	}
}

func setupCORSRouter(enabled bool, allowlist string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(NewCorsController(enabled, allowlist).Middleware())
	router.GET("/api/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	router.GET("/public", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return router
}

func setupCORSConfigDB(t *testing.T, apiKey string) {
	t.Helper()

	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	db, err := gorm.Open(sqlite.Open("file:"+name+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite test db: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sqlite test db handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})

	config.SetDb(db)
	if apiKey != "" {
		if err := config.Set(config.ApiKeyKey, apiKey); err != nil {
			t.Fatalf("set api key: %v", err)
		}
	}
}

func performCORSRequest(handler http.Handler, method, path, host, origin string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	request.Host = host
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
