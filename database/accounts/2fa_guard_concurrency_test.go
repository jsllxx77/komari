package accounts

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countTotpEvaluations 替换 totpStepMatcher，统计真正进入 TOTP 比对的次数。
// 每次比对都会停顿一下，让并发请求同时处于"校验中"，以暴露检查与记失败之间的空档。
func countTotpEvaluations(t *testing.T) *int64 {
	t.Helper()
	var evaluated int64
	original := totpStepMatcher
	totpStepMatcher = func(secret, code string, now time.Time) (int64, bool) {
		atomic.AddInt64(&evaluated, 1)
		time.Sleep(20 * time.Millisecond)
		return original(secret, code, now)
	}
	t.Cleanup(func() { totpStepMatcher = original })
	return &evaluated
}

func runConcurrently(n int, fn func()) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			fn()
		}()
	}
	close(start)
	wg.Wait()
}

func TestVerify2FaStrictConcurrentFailuresAreBounded(t *testing.T) {
	user, err := CreateAccount("totp-concurrent", "Secret-password1")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		Forget2FAState(user.UUID)
		_ = DeleteAccountByUsername("totp-concurrent")
	})
	if err := Enable2Fa(user.UUID, testTOTPSecret); err != nil {
		t.Fatalf("enable 2fa: %v", err)
	}
	evaluated := countTotpEvaluations(t)

	var accepted, locked int64
	runConcurrently(100, func() {
		ok, err := Verify2FaStrict(user.UUID, "000000")
		if ok {
			atomic.AddInt64(&accepted, 1)
		}
		if errors.Is(err, ErrTooMany2FAAttempts) {
			atomic.AddInt64(&locked, 1)
		}
	})

	if accepted != 0 {
		t.Fatalf("%d wrong codes were accepted", accepted)
	}
	if got := atomic.LoadInt64(evaluated); got > totpMaxFailures {
		t.Fatalf("%d concurrent wrong codes were evaluated, want at most %d", got, totpMaxFailures)
	}
	if locked < 100-totpMaxFailures {
		t.Fatalf("only %d requests were rejected as locked", locked)
	}
	// 并发结束后账号处于锁定状态，正确的验证码也不再被校验。
	code := totpCode(t, testTOTPSecret, time.Now().UTC())
	if _, err := Verify2FaStrict(user.UUID, code); !errors.Is(err, ErrTooMany2FAAttempts) {
		t.Fatalf("expected lockout after concurrent failures, got %v", err)
	}
}

func TestValidate2FACodeForSecretConcurrentFailuresAreBounded(t *testing.T) {
	owner := "pending-concurrent-owner"
	t.Cleanup(func() { Forget2FAState(owner) })
	evaluated := countTotpEvaluations(t)

	runConcurrently(100, func() {
		_, _, _ = Validate2FACodeForSecret(owner, testTOTPSecret, "000000")
	})

	if got := atomic.LoadInt64(evaluated); got > totpMaxFailures {
		t.Fatalf("%d concurrent wrong codes were evaluated, want at most %d", got, totpMaxFailures)
	}
	code := totpCode(t, testTOTPSecret, time.Now().UTC())
	if _, _, err := Validate2FACodeForSecret(owner, testTOTPSecret, code); !errors.Is(err, ErrTooMany2FAAttempts) {
		t.Fatalf("expected lockout after concurrent failures, got %v", err)
	}
}

func TestTotpGuardReservationReleasedOnSuccess(t *testing.T) {
	owner := "pending-release-owner"
	t.Cleanup(func() { Forget2FAState(owner) })
	code := totpCode(t, testTOTPSecret, time.Now().UTC())
	// 成功多次不应占满名额。
	for i := 0; i < totpMaxFailures*2; i++ {
		if _, ok, err := Validate2FACodeForSecret(owner, testTOTPSecret, code); err != nil || !ok {
			t.Fatalf("attempt %d: ok=%v err=%v", i, ok, err)
		}
	}
	// 4 次失败后成功一次会清零计数。
	for i := 0; i < totpMaxFailures-1; i++ {
		_, _, _ = Validate2FACodeForSecret(owner, testTOTPSecret, "000000")
	}
	if _, ok, err := Validate2FACodeForSecret(owner, testTOTPSecret, code); err != nil || !ok {
		t.Fatalf("success after failures: ok=%v err=%v", ok, err)
	}
	for i := 0; i < totpMaxFailures-1; i++ {
		if _, _, err := Validate2FACodeForSecret(owner, testTOTPSecret, "000000"); err != nil {
			t.Fatalf("failure counter was not reset by the success: %v", err)
		}
	}
}

func TestEnable2FaIfDisabledClaimsUsedStep(t *testing.T) {
	user, err := CreateAccount("totp-enable-replay", "Secret-password1")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		Forget2FAState(user.UUID)
		_ = DeleteAccountByUsername("totp-enable-replay")
	})

	code := totpCode(t, testTOTPSecret, time.Now().UTC())
	step, ok, err := Validate2FACodeForSecret(user.UUID, testTOTPSecret, code)
	if err != nil || !ok || step <= 0 {
		t.Fatalf("validate pending code: step=%d ok=%v err=%v", step, ok, err)
	}
	if err := Enable2FaIfDisabled(user.UUID, testTOTPSecret, step); err != nil {
		t.Fatalf("enable: %v", err)
	}
	// 启用时用过的验证码不能马上再用于登录。
	ok, err = Verify2FaStrict(user.UUID, code)
	if ok || !errors.Is(err, Err2FAReplay) {
		t.Fatalf("enable code replayed: ok=%v err=%v", ok, err)
	}
}
