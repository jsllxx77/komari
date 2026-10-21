package accounts

import (
	"testing"
	"time"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
)

// TestGetUserBySessionRejectsExpiredSession 确认 GetUserBySession 只返回未过期
// 会话对应的用户：过期会话必须返回错误，而不是继续解析出用户。
func TestGetUserBySessionRejectsExpiredSession(t *testing.T) {
	user, err := CreateAccount("session-expiry-user", "Session-password1")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() { _ = DeleteAccountByUsername("session-expiry-user") })

	session, err := CreateSession(user.UUID, 3600, "test-agent", "127.0.0.1", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	t.Cleanup(func() { _ = DeleteSession(session) })

	got, err := GetUserBySession(session)
	if err != nil || got.UUID != user.UUID {
		t.Fatalf("GetUserBySession(valid) = %q, %v; want uuid %q", got.UUID, err, user.UUID)
	}

	if err := dbcore.GetDBInstance().
		Model(&models.Session{}).
		Where("session = ?", session).
		Update("expires", time.Now().UTC().Add(-time.Hour)).Error; err != nil {
		t.Fatalf("expire session: %v", err)
	}

	if got, err := GetUserBySession(session); err == nil {
		t.Fatalf("GetUserBySession(expired) = %q, want an error", got.UUID)
	}
}
