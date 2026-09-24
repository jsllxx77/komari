package public

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
)

func TestLoginLimiterBlocksAfterLimitAndExpires(t *testing.T) {
	limiter := newLoginLimiter(3, time.Minute, 100)
	now := time.Unix(1_700_000_000, 0)

	for i := 0; i < 3; i++ {
		if ok, _ := limiter.Allow("203.0.113.1", now); !ok {
			t.Fatalf("attempt %d blocked before reaching the limit", i+1)
		}
		limiter.Fail("203.0.113.1", now)
	}
	ok, retryAfter := limiter.Allow("203.0.113.1", now.Add(10*time.Second))
	if ok {
		t.Fatal("address should be blocked after reaching the limit")
	}
	if retryAfter != 50*time.Second {
		t.Fatalf("retryAfter = %s, want 50s", retryAfter)
	}
	if ok, _ := limiter.Allow("203.0.113.2", now); !ok {
		t.Fatal("other addresses must not be affected")
	}
	if ok, _ := limiter.Allow("203.0.113.1", now.Add(time.Minute)); !ok {
		t.Fatal("address should be allowed again once the window has passed")
	}
}

func TestLoginLimiterResetClearsFailures(t *testing.T) {
	limiter := newLoginLimiter(2, time.Minute, 100)
	now := time.Now()
	limiter.Fail("203.0.113.1", now)
	limiter.Reset("203.0.113.1")
	limiter.Fail("203.0.113.1", now)
	if ok, _ := limiter.Allow("203.0.113.1", now); !ok {
		t.Fatal("a successful login should clear earlier failures")
	}
}

func TestLoginLimiterGroupsIPv6By64(t *testing.T) {
	limiter := newLoginLimiter(2, time.Minute, 100)
	now := time.Now()
	limiter.Fail("2001:db8:1:2::1", now)
	limiter.Fail("2001:db8:1:2:ffff::9", now)
	if ok, _ := limiter.Allow("2001:db8:1:2::abcd", now); ok {
		t.Fatal("addresses in the same /64 should share a failure budget")
	}
	if ok, _ := limiter.Allow("2001:db8:1:3::1", now); !ok {
		t.Fatal("a different /64 should not be blocked")
	}
}

func TestLoginLimiterStopsTrackingNewAddressesWhenFull(t *testing.T) {
	limiter := newLoginLimiter(1, time.Minute, 1)
	now := time.Now()
	limiter.Fail("203.0.113.1", now)
	limiter.Fail("203.0.113.2", now)
	if len(limiter.entries) != 1 {
		t.Fatalf("tracked %d addresses, want at most 1", len(limiter.entries))
	}
}

func postLogin(t *testing.T, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.POST("/login", Login)
	body, _ := json.Marshal(LoginRequest{Username: username, Password: password})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.RemoteAddr = "198.51.100.20:5555"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestLoginIsRateLimitedAfterRepeatedFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previous := loginAttempts
	loginAttempts = newLoginLimiter(3, time.Minute, 100)
	t.Cleanup(func() { loginAttempts = previous })

	if _, err := accounts.CreateAccount("ratelimited", "Correct-password1"); err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() { _ = accounts.DeleteAccountByUsername("ratelimited") })

	if w := postLogin(t, "ratelimited", "Correct-password1"); w.Code != http.StatusOK {
		t.Fatalf("initial login status = %d, want 200", w.Code)
	}
	for i := 0; i < 3; i++ {
		if w := postLogin(t, "ratelimited", "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("failed attempt %d status = %d, want 401", i+1, w.Code)
		}
	}
	w := postLogin(t, "ratelimited", "Correct-password1")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status after limit = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("rate limited response should include Retry-After")
	}
}
