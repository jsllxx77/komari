package accounts

import (
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

const testTOTPSecret = "JBSWY3DPEHPK3PXP"

func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

func TestVerify2FaStrictRejectsReplay(t *testing.T) {
	user, err := CreateAccount("totp-replay", "Secret-password1")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		Forget2FAState(user.UUID)
		_ = DeleteAccountByUsername("totp-replay")
	})
	if err := Enable2Fa(user.UUID, testTOTPSecret); err != nil {
		t.Fatalf("enable 2fa: %v", err)
	}

	code := totpCode(t, testTOTPSecret, time.Now().UTC())
	ok, err := Verify2FaStrict(user.UUID, code)
	if err != nil || !ok {
		t.Fatalf("first verification failed: ok=%v err=%v", ok, err)
	}

	ok, err = Verify2FaStrict(user.UUID, code)
	if ok {
		t.Fatal("a code from an already used time step was accepted twice")
	}
	if !errors.Is(err, Err2FAReplay) {
		t.Fatalf("replay error = %v, want %v", err, Err2FAReplay)
	}
}

func TestVerify2FaStrictLocksOutAfterFailures(t *testing.T) {
	user, err := CreateAccount("totp-lockout", "Secret-password1")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		Forget2FAState(user.UUID)
		_ = DeleteAccountByUsername("totp-lockout")
	})
	if err := Enable2Fa(user.UUID, testTOTPSecret); err != nil {
		t.Fatalf("enable 2fa: %v", err)
	}

	for i := 0; i < totpMaxFailures; i++ {
		ok, err := Verify2FaStrict(user.UUID, "000000")
		if err != nil {
			t.Fatalf("attempt %d: unexpected error: %v", i+1, err)
		}
		if ok {
			t.Fatal("a wrong code was accepted")
		}
	}

	code := totpCode(t, testTOTPSecret, time.Now().UTC())
	if _, err := Verify2FaStrict(user.UUID, code); !errors.Is(err, ErrTooMany2FAAttempts) {
		t.Fatalf("expected lockout after %d failures, got %v", totpMaxFailures, err)
	}

	// 清除状态后应恢复（模拟停用/更换 2FA）。
	Forget2FAState(user.UUID)
	ok, err := Verify2FaStrict(user.UUID, code)
	if err != nil || !ok {
		t.Fatalf("verification did not recover after reset: ok=%v err=%v", ok, err)
	}
}

func TestValidate2FACodeForSecret(t *testing.T) {
	now := time.Now().UTC()
	code := totpCode(t, testTOTPSecret, now)

	ok, err := Validate2FACodeForSecret("pending-owner", testTOTPSecret, code)
	if err != nil || !ok {
		t.Fatalf("valid code rejected: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { Forget2FAState("pending-owner") })

	ok, err = Validate2FACodeForSecret("pending-owner", testTOTPSecret, "000000")
	if ok {
		t.Fatal("wrong code accepted for pending secret")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := Validate2FACodeForSecret("pending-owner", "", code); err != nil {
		t.Fatalf("empty secret should not error: %v", err)
	}
}

func TestEnable2FaIfDisabledRefusesOverwrite(t *testing.T) {
	user, err := CreateAccount("totp-overwrite", "Secret-password1")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		Forget2FAState(user.UUID)
		_ = DeleteAccountByUsername("totp-overwrite")
	})

	if err := Enable2FaIfDisabled(user.UUID, testTOTPSecret); err != nil {
		t.Fatalf("first enable failed: %v", err)
	}
	if err := Enable2FaIfDisabled(user.UUID, "GEZDGNBVGY3TQOJQ"); !errors.Is(err, ErrTwoFactorAlreadyEnabled) {
		t.Fatalf("overwriting an existing secret must fail, got %v", err)
	}

	loaded, err := GetUserByUUID(user.UUID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	if loaded.TwoFactor != testTOTPSecret {
		t.Fatalf("secret was overwritten: %q", loaded.TwoFactor)
	}
}
