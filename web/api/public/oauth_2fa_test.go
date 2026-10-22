package public

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/pquerna/otp/totp"
)

const oauthTestTOTPSecret = "JBSWY3DPEHPK3PXP"

func oauthTestUser(t *testing.T, username string) string {
	t.Helper()
	user, err := accounts.CreateAccount(username, "Secret-password1")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		accounts.Forget2FAState(user.UUID)
		oauth2FAPending.Flush()
		_ = accounts.DeleteAccountByUsername(username)
	})
	return user.UUID
}

func newOAuthContext(t *testing.T, method, method2, body string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(method, method2, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	c.Request = req
	return c, w
}

func pendingCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == oauth2FACookie {
			return cookie
		}
	}
	t.Fatal("pending OAuth 2FA cookie was not set")
	return nil
}

func hasSessionCookie(w *httptest.ResponseRecorder) bool {
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "session_token" && cookie.Value != "" {
			return true
		}
	}
	return false
}

func TestOAuth2FALoginRequiresValidCode(t *testing.T) {
	uuid := oauthTestUser(t, "oauth-2fa-user")
	if err := accounts.Enable2Fa(uuid, oauthTestTOTPSecret); err != nil {
		t.Fatalf("enable 2fa: %v", err)
	}

	startCtx, startRec := newOAuthContext(t, http.MethodGet, oauth2FAPagePath, "")
	startPendingOAuth2FA(startCtx, uuid)
	cookie := pendingCookie(t, startRec)
	if hasSessionCookie(startRec) {
		t.Fatal("a pending 2FA login must not issue a session")
	}

	// 错误的验证码：不发会话。
	badCtx, badRec := newOAuthContext(t, http.MethodPost, oauth2FAPagePath, url.Values{"code": {"000000"}}.Encode())
	badCtx.Request.AddCookie(cookie)
	OAuth2FASubmit(badCtx)
	if hasSessionCookie(badRec) {
		t.Fatal("a wrong code issued a session")
	}
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("wrong code returned %d, want 400", badRec.Code)
	}

	// 正确的验证码：发会话并跳转后台。
	code, err := totp.GenerateCode(oauthTestTOTPSecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	okCtx, okRec := newOAuthContext(t, http.MethodPost, oauth2FAPagePath, url.Values{"code": {code}}.Encode())
	okCtx.Request.AddCookie(cookie)
	OAuth2FASubmit(okCtx)
	if !hasSessionCookie(okRec) {
		t.Fatalf("valid code did not create a session (status %d): %s", okRec.Code, okRec.Body.String())
	}
	if okCtx.Writer.Status() != http.StatusFound || okRec.Header().Get("Location") != "/admin/dashboard" {
		t.Fatalf("valid code did not redirect to the dashboard: status=%d location=%q", okCtx.Writer.Status(), okRec.Header().Get("Location"))
	}

	var count int64
	if err := dbcore.GetDBInstance().Model(&models.Session{}).Where("uuid = ?", uuid).Count(&count).Error; err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if count == 0 {
		t.Fatal("session was not persisted")
	}

	// 同一个待验证令牌不能再用一次。
	replayCtx, replayRec := newOAuthContext(t, http.MethodPost, oauth2FAPagePath, url.Values{"code": {code}}.Encode())
	replayCtx.Request.AddCookie(cookie)
	OAuth2FASubmit(replayCtx)
	if hasSessionCookie(replayRec) {
		t.Fatal("a consumed pending token was accepted again")
	}
}

func TestOAuth2FAInvalidatesAfterTooManyAttempts(t *testing.T) {
	uuid := oauthTestUser(t, "oauth-2fa-attempts")
	if err := accounts.Enable2Fa(uuid, oauthTestTOTPSecret); err != nil {
		t.Fatalf("enable 2fa: %v", err)
	}

	startCtx, startRec := newOAuthContext(t, http.MethodGet, oauth2FAPagePath, "")
	startPendingOAuth2FA(startCtx, uuid)
	cookie := pendingCookie(t, startRec)

	code, err := totp.GenerateCode(oauthTestTOTPSecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	for i := 0; i < oauth2FAMaxAttempts; i++ {
		ctx, rec := newOAuthContext(t, http.MethodPost, oauth2FAPagePath, url.Values{"code": {"000000"}}.Encode())
		ctx.Request.AddCookie(cookie)
		OAuth2FASubmit(ctx)
		if hasSessionCookie(rec) {
			t.Fatal("wrong code issued a session")
		}
	}

	afterCtx, afterRec := newOAuthContext(t, http.MethodPost, oauth2FAPagePath, url.Values{"code": {code}}.Encode())
	afterCtx.Request.AddCookie(cookie)
	OAuth2FASubmit(afterCtx)
	if hasSessionCookie(afterRec) {
		t.Fatal("pending token survived more than the allowed number of failures")
	}
}

// 并发提交同一个待验证令牌：最多校验 oauth2FAMaxAttempts 次，之后令牌作废。
func TestOAuth2FAConcurrentAttemptsAreBounded(t *testing.T) {
	uuid := oauthTestUser(t, "oauth-2fa-concurrent")
	if err := accounts.Enable2Fa(uuid, oauthTestTOTPSecret); err != nil {
		t.Fatalf("enable 2fa: %v", err)
	}

	var evaluated int64
	original := oauth2FAVerify
	oauth2FAVerify = func(userUUID, code string) (bool, error) {
		atomic.AddInt64(&evaluated, 1)
		time.Sleep(20 * time.Millisecond)
		return false, nil
	}
	t.Cleanup(func() { oauth2FAVerify = original })

	startCtx, startRec := newOAuthContext(t, http.MethodGet, oauth2FAPagePath, "")
	startPendingOAuth2FA(startCtx, uuid)
	cookie := pendingCookie(t, startRec)

	var wg sync.WaitGroup
	start := make(chan struct{})
	var sessions int64
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, rec := newOAuthContext(t, http.MethodPost, oauth2FAPagePath, url.Values{"code": {"000000"}}.Encode())
			ctx.Request.AddCookie(cookie)
			OAuth2FASubmit(ctx)
			if hasSessionCookie(rec) {
				atomic.AddInt64(&sessions, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if sessions != 0 {
		t.Fatalf("%d wrong codes created a session", sessions)
	}
	if got := atomic.LoadInt64(&evaluated); got > oauth2FAMaxAttempts {
		t.Fatalf("%d concurrent attempts were evaluated, want at most %d", got, oauth2FAMaxAttempts)
	}
	if _, ok := oauth2FAPending.Get(cookie.Value); ok {
		t.Fatal("pending token survived after the attempt limit was reached")
	}

	// 令牌作废后正确的验证码也不能登录。
	oauth2FAVerify = original
	code, err := totp.GenerateCode(oauthTestTOTPSecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	ctx, rec := newOAuthContext(t, http.MethodPost, oauth2FAPagePath, url.Values{"code": {code}}.Encode())
	ctx.Request.AddCookie(cookie)
	OAuth2FASubmit(ctx)
	if hasSessionCookie(rec) {
		t.Fatal("an invalidated pending token still created a session")
	}
}

func TestOAuth2FAFormRedirectsWithoutPendingLogin(t *testing.T) {
	ctx, rec := newOAuthContext(t, http.MethodGet, oauth2FAPagePath, "")
	ctx.Request.AddCookie(&http.Cookie{Name: oauth2FACookie, Value: "not-a-real-token"})
	OAuth2FAForm(ctx)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("expected a redirect home, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestOAuth2FAFormRejectsSubmissionsWithoutCookie(t *testing.T) {
	ctx, rec := newOAuthContext(t, http.MethodPost, oauth2FAPagePath, url.Values{"code": {"123456"}}.Encode())
	OAuth2FASubmit(ctx)
	if hasSessionCookie(rec) {
		t.Fatal("submission without a pending token created a session")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
