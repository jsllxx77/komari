package jsonrpc

// admin.misc_sessions_test.go
// F-18：admin:getSessions 不得再向前端返回 sessions 表的明文 session。
// 这里覆盖四点：返回结构不含明文、含 id/current 标记、deleteSession 支持 id、
// 以及过渡期明文删除仍然可用。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/pkg/rpc"
)

func TestSessionIDIsStableHashPrefix(t *testing.T) {
	const token = "session-token-for-id-check"

	sum := sha256.Sum256([]byte(token))
	want := hex.EncodeToString(sum[:])[:16]

	got := sessionID(token)
	if got != want {
		t.Fatalf("sessionID(%q) = %q, want %q", token, got, want)
	}
	if len(got) != 16 {
		t.Fatalf("sessionID length = %d, want 16 hex chars", len(got))
	}
	if got == token {
		t.Fatal("sessionID must not equal the plaintext token")
	}
	if again := sessionID(token); again != got {
		t.Fatalf("sessionID is not deterministic: %q != %q", again, got)
	}
	if sessionID("another-token") == got {
		t.Fatal("different sessions must not share an id in this test fixture")
	}
}

func TestAdminGetSessionsDoesNotLeakPlaintextSession(t *testing.T) {
	user := createSessionTestUser(t, "get-sessions-hide-user")
	currentToken := createSessionTestSession(t, user.UUID, "current-agent")
	otherToken := createSessionTestSession(t, user.UUID, "other-agent")

	ctx := rpc.NewContextWithMeta(context.Background(), &rpc.ContextMeta{
		Permission:   "admin",
		UserUUID:     user.UUID,
		SessionToken: currentToken,
	})
	result, jerr := adminGetSessions(ctx, &rpc.JsonRpcRequest{})
	if jerr != nil {
		t.Fatalf("adminGetSessions returned error: %+v", jerr)
	}

	res, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T, want map[string]any", result)
	}
	// 顶层旧的 current 字段保存的就是明文 token，必须不再出现。
	if _, exists := res["current"]; exists {
		t.Fatal("top-level `current` must not be returned (it used to leak the plaintext token)")
	}

	// 整个响应序列化后不得出现任一明文 session，也不得有 `session` 字段。
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, token := range []string{currentToken, otherToken} {
		if strings.Contains(string(raw), token) {
			t.Fatalf("response leaked a plaintext session token: %s", raw)
		}
	}
	if strings.Contains(string(raw), `"session"`) {
		t.Fatalf("response still contains a `session` field: %s", raw)
	}

	data, ok := res["data"].([]sessionResponse)
	if !ok {
		t.Fatalf("data type = %T, want []sessionResponse", res["data"])
	}
	var currentResp, otherResp *sessionResponse
	for i := range data {
		switch data[i].ID {
		case sessionID(currentToken):
			currentResp = &data[i]
		case sessionID(otherToken):
			otherResp = &data[i]
		}
	}
	if currentResp == nil || otherResp == nil {
		t.Fatalf("sessions missing from response: %+v", data)
	}
	if !currentResp.Current {
		t.Fatal("the caller's own session must be marked current")
	}
	if otherResp.Current {
		t.Fatal("a different session must not be marked current")
	}
	if currentResp.UUID != user.UUID {
		t.Fatalf("uuid = %q, want %q", currentResp.UUID, user.UUID)
	}
	if currentResp.UserAgent != "current-agent" {
		t.Fatalf("user_agent = %q, want current-agent", currentResp.UserAgent)
	}
}

func TestAdminDeleteSessionByID(t *testing.T) {
	user := createSessionTestUser(t, "delete-session-by-id-user")
	target := createSessionTestSession(t, user.UUID, "delete-by-id-target")
	keep := createSessionTestSession(t, user.UUID, "delete-by-id-keep")

	_, jerr := adminDeleteSession(context.Background(), &rpc.JsonRpcRequest{
		Params: map[string]any{"id": sessionID(target)},
	})
	if jerr != nil {
		t.Fatalf("delete by id returned error: %+v", jerr)
	}
	if _, err := accounts.GetSession(target); err == nil {
		t.Fatal("target session still exists after delete by id")
	}
	if _, err := accounts.GetSession(keep); err != nil {
		t.Fatalf("unrelated session was deleted: %v", err)
	}
}

func TestAdminDeleteSessionByPlaintextStillWorks(t *testing.T) {
	user := createSessionTestUser(t, "delete-session-plain-user")
	token := createSessionTestSession(t, user.UUID, "delete-plain-target")

	_, jerr := adminDeleteSession(context.Background(), &rpc.JsonRpcRequest{
		Params: map[string]any{"session": token},
	})
	if jerr != nil {
		t.Fatalf("delete by plaintext returned error: %+v", jerr)
	}
	if _, err := accounts.GetSession(token); err == nil {
		t.Fatal("session still exists after transitional plaintext delete")
	}
}

func TestAdminDeleteSessionRejectsUnknownID(t *testing.T) {
	user := createSessionTestUser(t, "delete-session-unknown-user")
	token := createSessionTestSession(t, user.UUID, "delete-unknown-keep")

	_, jerr := adminDeleteSession(context.Background(), &rpc.JsonRpcRequest{
		Params: map[string]any{"id": "0000000000000000"},
	})
	if jerr == nil {
		t.Fatal("delete with an unknown id must return an error")
	}
	if jerr.Code != rpc.InvalidParams {
		t.Fatalf("error code = %d, want InvalidParams", jerr.Code)
	}
	if _, err := accounts.GetSession(token); err != nil {
		t.Fatalf("unknown id must not delete any session: %v", err)
	}
}

func createSessionTestUser(t *testing.T, username string) models.User {
	t.Helper()
	user, err := accounts.CreateAccount(username, "Session-test-password1")
	if err != nil {
		t.Fatalf("create account %q: %v", username, err)
	}
	t.Cleanup(func() { _ = accounts.DeleteAccountByUsername(username) })
	return user
}

func createSessionTestSession(t *testing.T, uuid, userAgent string) string {
	t.Helper()
	token, err := accounts.CreateSession(uuid, 3600, userAgent, "127.0.0.1", "password")
	if err != nil {
		t.Fatalf("create session for %q: %v", userAgent, err)
	}
	t.Cleanup(func() { _ = accounts.DeleteSession(token) })
	return token
}
