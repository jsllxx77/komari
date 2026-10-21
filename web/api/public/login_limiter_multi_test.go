package public

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
)

// failOnce 通过 Begin/ConfirmFailure 记录一次失败尝试。
func failOnce(t *testing.T, limiter *loginLimiter, ip, username string, now time.Time) {
	t.Helper()
	allowed, _, res := limiter.Begin(ip, username, now)
	if !allowed {
		t.Fatalf("attempt from %s/%s blocked before reaching the limit", ip, username)
	}
	limiter.ConfirmFailure(res, now)
}

func TestLoginLimiterIPUsernameHardLock(t *testing.T) {
	limiter := newLoginLimiter(10, 15*time.Minute, 1000)
	now := time.Unix(1_700_000_000, 0)

	for i := 0; i < 10; i++ {
		allowed, _, res := limiter.Begin("203.0.113.10", "alice", now)
		if !allowed {
			t.Fatalf("attempt %d blocked before reaching the limit", i+1)
		}
		if hit := limiter.ConfirmFailure(res, now); hit != (i == 9) {
			t.Fatalf("attempt %d hitLimit = %v, want %v", i+1, hit, i == 9)
		}
	}

	allowed, retryAfter, res := limiter.Begin("203.0.113.10", "alice", now)
	if allowed {
		t.Fatal("(IP, username) must be locked after 10 failures")
	}
	if res != nil {
		t.Fatal("rejected Begin must not return a reservation")
	}
	if retryAfter <= 0 || retryAfter > 15*time.Minute {
		t.Fatalf("retryAfter = %s, want within (0, 15m]", retryAfter)
	}

	// IP 维度同样是硬锁：同一 IP 换用户名也应被拒绝。
	if allowed, _, _ := limiter.Begin("203.0.113.10", "bob", now); allowed {
		t.Fatal("IP dimension must be locked after 10 failures")
	}
	// 用户名维度不硬锁：换一个 IP 仍然可以尝试。
	if allowed, _, _ := limiter.Begin("203.0.113.11", "alice", now); !allowed {
		t.Fatal("username dimension must not hard-lock a different IP")
	}
}

func TestLoginLimiterSuccessClearsFailures(t *testing.T) {
	limiter := newLoginLimiter(2, time.Minute, 100)
	now := time.Unix(1_700_000_000, 0)

	failOnce(t, limiter, "203.0.113.20", "eve", now)
	allowed, _, res := limiter.Begin("203.0.113.20", "eve", now)
	if !allowed {
		t.Fatal("one failure should not exhaust a limit of two")
	}
	limiter.ConfirmSuccess(res, now)
	if allowed, _, _ := limiter.Begin("203.0.113.20", "eve", now); !allowed {
		t.Fatal("a successful login should clear earlier failures")
	}
}

func TestLoginLimiterUsernameDelayGrowsAndDoesNotHardLock(t *testing.T) {
	limiter := newLoginLimiter(1000, time.Minute, 10_000)
	now := time.Unix(1_700_000_000, 0)

	// 20 次失败仍不产生延迟。
	for i := 0; i < 20; i++ {
		failOnce(t, limiter, fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), "bob", now)
	}
	if delay := limiter.FailureDelay("bob", now); delay != 0 {
		t.Fatalf("delay after 20 failures = %s, want 0", delay)
	}

	// 第 21 次失败后开始延迟 1s。
	failOnce(t, limiter, "10.9.0.1", "bob", now)
	if delay := limiter.FailureDelay("bob", now); delay != time.Second {
		t.Fatalf("delay after 21 failures = %s, want 1s", delay)
	}

	// 继续累积到 25 次，延迟封顶 5s。
	for i := 22; i <= 25; i++ {
		failOnce(t, limiter, fmt.Sprintf("10.9.0.%d", i-20), "bob", now)
	}
	if delay := limiter.FailureDelay("bob", now); delay != 5*time.Second {
		t.Fatalf("delay after 25 failures = %s, want 5s", delay)
	}

	// 用户名维度不硬锁：来自全新 IP 的尝试仍然放行。
	if allowed, _, _ := limiter.Begin("10.10.0.1", "bob", now); !allowed {
		t.Fatal("username dimension must never hard-lock")
	}
}

func TestLoginLimiterConcurrentBeginNeverExceedsLimit(t *testing.T) {
	const (
		limit    = 10
		requests = 50
	)
	limiter := newLoginLimiter(limit, time.Minute, 1000)
	now := time.Unix(1_700_000_000, 0)

	var (
		allowedCount int64
		mu           sync.Mutex
		reservations []*loginReservation
		wg           sync.WaitGroup
	)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _, res := limiter.Begin("198.51.100.5", "carol", now)
			if !allowed {
				return
			}
			atomic.AddInt64(&allowedCount, 1)
			mu.Lock()
			reservations = append(reservations, res)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&allowedCount); got > limit {
		t.Fatalf("concurrent allowed = %d, want <= %d", got, limit)
	} else if got != limit {
		t.Fatalf("concurrent allowed = %d, want exactly %d", got, limit)
	}
	for _, res := range reservations {
		limiter.Cancel(res)
	}
}

func TestLoginLimiterTableFullStillRateLimits(t *testing.T) {
	limiter := newLoginLimiter(2, time.Minute, 1)
	now := time.Unix(1_700_000_000, 0)

	// 占满唯一的独立条目槽位。
	failOnce(t, limiter, "10.0.0.1", "u", now)
	if len(limiter.entries) != 1 {
		t.Fatalf("tracked entries = %d, want 1", len(limiter.entries))
	}

	// 表满后新地址进入共享桶，仍有少量配额。
	failOnce(t, limiter, "10.0.0.2", "u", now)
	// 共享桶耗尽后，新地址必须被拒绝，而不是直接放行。
	allowed, retryAfter, res := limiter.Begin("10.0.0.3", "u", now)
	if allowed {
		t.Fatal("table full and shared bucket exhausted must still rate limit")
	}
	if res != nil {
		t.Fatal("rejected Begin must not return a reservation")
	}
	if retryAfter <= 0 {
		t.Fatalf("retryAfter = %s, want > 0", retryAfter)
	}
	if len(limiter.entries) != 1 {
		t.Fatalf("tracked entries = %d, want 1 (overflow must not grow the map)", len(limiter.entries))
	}
}

func TestLoginLimiterBeginGroupsIPv6By64(t *testing.T) {
	limiter := newLoginLimiter(2, time.Minute, 1000)
	now := time.Unix(1_700_000_000, 0)

	failOnce(t, limiter, "2001:db8:1:2::1", "dave", now)
	failOnce(t, limiter, "2001:db8:1:2:ffff::9", "dave", now)

	if allowed, _, _ := limiter.Begin("2001:db8:1:2::abcd", "dave", now); allowed {
		t.Fatal("addresses in the same /64 should share the IP budget")
	}
	if allowed, _, _ := limiter.Begin("2001:db8:1:3::1", "dave", now); !allowed {
		t.Fatal("a different /64 should not be blocked")
	}
}

func TestLoginCorrectPasswordRejectedAfterIPUsernameFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousLimiter := loginAttempts
	loginAttempts = newLoginLimiter(10, 15*time.Minute, 1000)
	t.Cleanup(func() { loginAttempts = previousLimiter })

	previousSleep := loginFailureSleep
	loginFailureSleep = func(time.Duration) {}
	t.Cleanup(func() { loginFailureSleep = previousSleep })

	const (
		username = "locktarget"
		password = "Correct-password1"
	)
	if _, err := accounts.CreateAccount(username, password); err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() { _ = accounts.DeleteAccountByUsername(username) })

	for i := 0; i < 10; i++ {
		if w := postLogin(t, username, "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("failed attempt %d status = %d, want 401", i+1, w.Code)
		}
	}
	w := postLogin(t, username, password)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("correct password after 10 failures status = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("rate limited response should include Retry-After")
	}
}

func TestLoginUsernameDelaySlowsFailuresWithoutLocking(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousLimiter := loginAttempts
	loginAttempts = newLoginLimiter(1000, 15*time.Minute, 10_000)
	t.Cleanup(func() { loginAttempts = previousLimiter })

	previousNow := loginNow
	fixed := time.Unix(1_700_000_000, 0)
	loginNow = func() time.Time { return fixed }
	t.Cleanup(func() { loginNow = previousNow })

	previousSleep := loginFailureSleep
	var sleeps []time.Duration
	loginFailureSleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	t.Cleanup(func() { loginFailureSleep = previousSleep })

	const (
		username = "delayuser"
		password = "Correct-password1"
	)
	if _, err := accounts.CreateAccount(username, password); err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() { _ = accounts.DeleteAccountByUsername(username) })

	for i := 0; i < 20; i++ {
		if w := postLogin(t, username, "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("failed attempt %d status = %d, want 401", i+1, w.Code)
		}
	}
	if len(sleeps) != 20 {
		t.Fatalf("sleep calls = %d, want 20", len(sleeps))
	}
	for i, d := range sleeps {
		if d != 0 {
			t.Fatalf("attempt %d delay = %s, want 0 while under threshold", i+1, d)
		}
	}

	if w := postLogin(t, username, "wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("21st failed attempt status = %d, want 401", w.Code)
	}
	if len(sleeps) != 21 {
		t.Fatalf("sleep calls = %d, want 21", len(sleeps))
	}
	if got := sleeps[20]; got != time.Second {
		t.Fatalf("delay after threshold = %s, want 1s", got)
	}

	// 用户名维度只降速不硬锁：正确密码仍然成功。
	if w := postLogin(t, username, password); w.Code != http.StatusOK {
		t.Fatalf("correct password after delay threshold status = %d, want 200", w.Code)
	}
}

func TestSharedLimiterKeyDetection(t *testing.T) {
	cases := []struct {
		name       string
		clientIP   string
		remoteAddr string
		want       bool
	}{
		{"loopback v4", "127.0.0.1", "127.0.0.1:5000", true},
		{"loopback v6", "::1", "[::1]:5000", true},
		{"private peer without xff", "192.168.1.5", "192.168.1.5:5000", true},
		{"public direct client", "203.0.113.9", "203.0.113.9:5000", false},
		{"xff resolved public", "198.51.100.7", "192.168.1.5:5000", false},
		{"xff resolved via loopback proxy", "203.0.113.9", "127.0.0.1:5000", false},
		{"unparsable client ip", "not-an-ip", "127.0.0.1:5000", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := sharedLimiterKey(tt.clientIP, tt.remoteAddr); got != tt.want {
				t.Fatalf("sharedLimiterKey(%q, %q) = %v, want %v", tt.clientIP, tt.remoteAddr, got, tt.want)
			}
		})
	}
}

func TestSharedKeyWarningIsThrottledHourly(t *testing.T) {
	sharedKeyLastWarn.Store(0)
	t.Cleanup(func() { sharedKeyLastWarn.Store(0) })

	base := time.Unix(1_700_000_000, 0)
	var messages []string
	warn := func(message string) { messages = append(messages, message) }

	if !sharedKeyWarnOnce("127.0.0.1", "127.0.0.1:5000", base, warn) {
		t.Fatal("first warning should fire")
	}
	if sharedKeyWarnOnce("127.0.0.1", "127.0.0.1:5000", base.Add(30*time.Minute), warn) {
		t.Fatal("warning within an hour should be suppressed")
	}
	if !sharedKeyWarnOnce("127.0.0.1", "127.0.0.1:5000", base.Add(61*time.Minute), warn) {
		t.Fatal("warning should fire again after an hour")
	}
	if sharedKeyWarnOnce("203.0.113.9", "203.0.113.9:5000", base.Add(2*time.Hour), warn) {
		t.Fatal("normal direct client must not warn")
	}
	if len(messages) != 2 {
		t.Fatalf("warnings = %d, want 2", len(messages))
	}
}
