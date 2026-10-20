package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/pquerna/otp/totp"
)

func twoFATestContext(t *testing.T, userUUID, target, body string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if body != "" {
		c.Request.Header.Set("Content-Type", "application/json")
	}
	c.Set("uuid", userUUID)
	return c, w
}

func setupTwoFATestUser(t *testing.T, username string) string {
	t.Helper()
	flags.DatabaseType = "sqlite"
	flags.DatabaseFile = "file:web_admin_two_factor?mode=memory&cache=shared"
	user, err := accounts.CreateAccount(username, "Secret-password1")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		pending2FASecrets.Delete(user.UUID)
		accounts.Forget2FAState(user.UUID)
		_ = accounts.DeleteAccountByUsername(username)
	})
	return user.UUID
}

func TestGenerate2FARefusesWhenAlreadyEnabled(t *testing.T) {
	uuid := setupTwoFATestUser(t, "totp-admin-existing")
	if err := accounts.Enable2Fa(uuid, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("enable 2fa: %v", err)
	}

	c, w := twoFATestContext(t, uuid, "/api/admin/2fa/generate", "")
	Generate2FA(c)

	if w.Code != http.StatusConflict {
		t.Fatalf("generate with 2FA enabled returned %d, want 409", w.Code)
	}
	if _, ok := pending2FASecrets.Get(uuid); ok {
		t.Fatal("a new pending secret must not be issued while 2FA is enabled")
	}
}

func TestEnable2FAIgnoresClientSuppliedSecret(t *testing.T) {
	uuid := setupTwoFATestUser(t, "totp-admin-cookie")

	// 生成待启用密钥（只存在服务端）。
	genCtx, genRec := twoFATestContext(t, uuid, "/api/admin/2fa/generate", "")
	Generate2FA(genCtx)
	if genRec.Code != http.StatusOK {
		t.Fatalf("generate returned %d", genRec.Code)
	}
	pending, ok := pending2FASecrets.Get(uuid)
	if !ok {
		t.Fatal("pending secret was not stored server-side")
	}
	pendingSecret, _ := pending.(string)
	if pendingSecret == "" {
		t.Fatal("pending secret is empty")
	}

	// 攻击者自选密钥并算出对应验证码，同时伪造旧的 2fa_secret cookie。
	attackerSecret := "GEZDGNBVGY3TQOJQ"
	attackerCode, err := totp.GenerateCode(attackerSecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate attacker code: %v", err)
	}
	c, w := twoFATestContext(t, uuid, "/api/admin/2fa/enable?code="+attackerCode, "")
	c.Request.AddCookie(&http.Cookie{Name: "2fa_secret", Value: attackerSecret})
	Enable2FA(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("enable with a client-supplied secret returned %d, want 400", w.Code)
	}

	user, err := accounts.GetUserByUUID(uuid)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	if user.TwoFactor != "" {
		t.Fatalf("2FA was enabled with the attacker's secret: %q", user.TwoFactor)
	}

	// 正确的验证码走同一路径应当成功。
	code, err := totp.GenerateCode(pendingSecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	okCtx, okRec := twoFATestContext(t, uuid, "/api/admin/2fa/enable", `{"2fa_code":"`+code+`"}`)
	Enable2FA(okCtx)
	if okRec.Code != http.StatusOK {
		t.Fatalf("enable with the pending secret returned %d: %s", okRec.Code, okRec.Body.String())
	}
	user, err = accounts.GetUserByUUID(uuid)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	if user.TwoFactor != pendingSecret {
		t.Fatalf("stored secret = %q, want the server-side pending secret", user.TwoFactor)
	}
	if _, ok := pending2FASecrets.Get(uuid); ok {
		t.Fatal("pending secret was not cleared after a successful enable")
	}
}

func TestEnable2FARejectsWrongCode(t *testing.T) {
	uuid := setupTwoFATestUser(t, "totp-admin-wrong")

	genCtx, _ := twoFATestContext(t, uuid, "/api/admin/2fa/generate", "")
	Generate2FA(genCtx)

	c, w := twoFATestContext(t, uuid, "/api/admin/2fa/enable", `{"2fa_code":"000000"}`)
	Enable2FA(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong code returned %d, want 400", w.Code)
	}
}

func TestEnable2FARequiresPendingSecret(t *testing.T) {
	uuid := setupTwoFATestUser(t, "totp-admin-expired")
	c, w := twoFATestContext(t, uuid, "/api/admin/2fa/enable", `{"2fa_code":"123456"}`)
	Enable2FA(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("enable without a pending secret returned %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "expired") {
		t.Fatalf("unexpected message: %s", w.Body.String())
	}
}
