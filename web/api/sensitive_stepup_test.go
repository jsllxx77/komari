package api

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/pquerna/otp/totp"
)

func TestMain(m *testing.M) {
	flags.DatabaseType = flags.DatabaseTypeSQLite
	flags.DatabaseFile = "file:web_api_sensitive_test?mode=memory&cache=shared"

	db := dbcore.GetDBInstance()
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	os.Exit(m.Run())
}

const stepUpTestSecret = "JBSWY3DPEHPK3PXP"

func stepUpTestUser(t *testing.T, username string, with2FA bool) (string, string) {
	t.Helper()
	user, err := accounts.CreateAccount(username, "Secret-password1")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		accounts.Forget2FAState(user.UUID)
		_ = accounts.DeleteSessionsExcept(user.UUID, "")
		_ = accounts.DeleteAccountByUsername(username)
	})
	if with2FA {
		if err := accounts.Enable2Fa(user.UUID, stepUpTestSecret); err != nil {
			t.Fatalf("enable 2fa: %v", err)
		}
	}
	session, err := accounts.CreateSession(user.UUID, 3600, "test", "127.0.0.1", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return user.UUID, session
}

func TestSensitive2FARequiresCodeWithoutStepUp(t *testing.T) {
	uuid, session := stepUpTestUser(t, "stepup-none", true)

	err := VerifySensitive2FAFor(uuid, session, false, func() string { return "" })
	if err == nil || !strings.Contains(err.Error(), "2FA code is required") {
		t.Fatalf("expected a 2FA requirement, got %v", err)
	}
}

func TestSensitive2FAUsesStepUpWindow(t *testing.T) {
	uuid, session := stepUpTestUser(t, "stepup-window", true)

	if err := accounts.MarkSessionMFAVerified(session); err != nil {
		t.Fatalf("mark verified: %v", err)
	}
	if err := VerifySensitive2FAFor(uuid, session, false, func() string { return "" }); err != nil {
		t.Fatalf("fresh step-up window should pass without a code, got %v", err)
	}

	// 把时间往前拨 11 分钟，窗口应失效。
	db := dbcore.GetDBInstance()
	old := time.Now().UTC().Add(-11 * time.Minute)
	if err := db.Model(&models.Session{}).Where("session = ?", session).Update("mfa_verified_at", old).Error; err != nil {
		t.Fatalf("backdate verified at: %v", err)
	}
	if err := VerifySensitive2FAFor(uuid, session, false, func() string { return "" }); err == nil {
		t.Fatal("an expired step-up window must require a code again")
	}
}

func TestSensitive2FAFreshCodeExtendsStepUp(t *testing.T) {
	uuid, session := stepUpTestUser(t, "stepup-code", true)

	code, err := totp.GenerateCode(stepUpTestSecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if err := VerifySensitive2FAFor(uuid, session, false, func() string { return code }); err != nil {
		t.Fatalf("valid code rejected: %v", err)
	}
	verifiedAt, ok, err := accounts.SessionMFAVerifiedAt(session)
	if err != nil {
		t.Fatalf("read verified at: %v", err)
	}
	if !ok || time.Since(verifiedAt) > time.Minute {
		t.Fatalf("session was not marked as verified: ok=%v at=%v", ok, verifiedAt)
	}
}

func TestSensitive2FAWrongCodeRejected(t *testing.T) {
	uuid, session := stepUpTestUser(t, "stepup-wrong", true)

	err := VerifySensitive2FAFor(uuid, session, false, func() string { return "000000" })
	if err == nil || !strings.Contains(err.Error(), "Invalid 2FA code") {
		t.Fatalf("expected invalid code error, got %v", err)
	}
}

func TestSensitive2FASkipsUsersWithoutTwoFactorAndAPIKeys(t *testing.T) {
	uuid, session := stepUpTestUser(t, "stepup-disabled", false)
	if err := VerifySensitive2FAFor(uuid, session, false, func() string { return "" }); err != nil {
		t.Fatalf("accounts without 2FA must not be asked for a code: %v", err)
	}

	uuid2, session2 := stepUpTestUser(t, "stepup-apikey", true)
	if err := VerifySensitive2FAFor(uuid2, session2, true, func() string { return "" }); err != nil {
		t.Fatalf("API key callers are exempt: %v", err)
	}
}
