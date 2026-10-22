package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/web/api"
)

func TestMain(m *testing.M) {
	flags.DatabaseType = flags.DatabaseTypeSQLite
	flags.DatabaseFile = "file:web_router_test?mode=memory&cache=shared"

	db := dbcore.GetDBInstance()
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	os.Exit(m.Run())
}

const routerTestTOTPSecret = "JBSWY3DPEHPK3PXP"

// newAdminTestEngine 用真实的路由注册函数搭一个只含身份识别与管理员路由的引擎，
// 断言的是"路由上确实挂了哪些中间件"，而不是单独调用某个中间件。
func newAdminTestEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(api.IdentityMiddleware())
	registerAdminRoutes(r)
	return r
}

// routerTestSession 创建一个启用了 2FA 的管理员账号及其 cookie 会话。
func routerTestSession(t *testing.T, username string) (string, string) {
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
	if err := accounts.Enable2Fa(user.UUID, routerTestTOTPSecret); err != nil {
		t.Fatalf("enable 2fa: %v", err)
	}
	session, err := accounts.CreateSession(user.UUID, 3600, "test", "127.0.0.1", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return user.UUID, session
}

func serveWithSession(r *gin.Engine, method, target, body, session string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(&http.Cookie{Name: "session_token", Value: session})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

type twoFactorStatusBody struct {
	Status string                     `json:"status"`
	Data   map[string]json.RawMessage `json:"data"`
}

func readTwoFactorStatus(t *testing.T, r *gin.Engine, session string) (enabled bool, validUntil, window int64) {
	t.Helper()
	w := serveWithSession(r, http.MethodGet, "/api/admin/2fa/status", "", session)
	if w.Code != http.StatusOK {
		t.Fatalf("status returned %d: %s", w.Code, w.Body.String())
	}
	var body twoFactorStatusBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	// 字段名是与前端的约定，必须一个不差。
	for _, key := range []string{"enabled", "step_up_valid_until", "window_seconds"} {
		if _, ok := body.Data[key]; !ok {
			t.Fatalf("response is missing %q: %s", key, w.Body.String())
		}
	}
	if len(body.Data) != 3 {
		t.Fatalf("unexpected fields in %s", w.Body.String())
	}
	_ = json.Unmarshal(body.Data["enabled"], &enabled)
	_ = json.Unmarshal(body.Data["step_up_valid_until"], &validUntil)
	_ = json.Unmarshal(body.Data["window_seconds"], &window)
	return enabled, validUntil, window
}

func TestTwoFactorStatusReportsStepUpWindow(t *testing.T) {
	r := newAdminTestEngine()
	_, session := routerTestSession(t, "router-2fa-status")

	enabled, validUntil, window := readTwoFactorStatus(t, r, session)
	if !enabled || validUntil != 0 || window != 600 {
		t.Fatalf("before step-up: enabled=%v valid_until=%d window=%d", enabled, validUntil, window)
	}

	before := time.Now().Unix()
	if err := accounts.MarkSessionMFAVerified(session); err != nil {
		t.Fatalf("mark verified: %v", err)
	}
	_, validUntil, _ = readTwoFactorStatus(t, r, session)
	if validUntil < before+600-1 || validUntil > time.Now().Unix()+600+1 {
		t.Fatalf("valid_until = %d, want about %d", validUntil, before+600)
	}

	// 窗口过期后回到 0。
	old := time.Now().UTC().Add(-11 * time.Minute)
	if err := dbcore.GetDBInstance().Model(&models.Session{}).Where("session = ?", session).Update("mfa_verified_at", old).Error; err != nil {
		t.Fatalf("backdate: %v", err)
	}
	_, validUntil, _ = readTwoFactorStatus(t, r, session)
	if validUntil != 0 {
		t.Fatalf("expired window reported valid_until = %d", validUntil)
	}
}

func TestTwoFactorStatusWithout2FAAndUnauthenticated(t *testing.T) {
	r := newAdminTestEngine()
	user, err := accounts.CreateAccount("router-2fa-status-off", "Secret-password1")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		_ = accounts.DeleteSessionsExcept(user.UUID, "")
		_ = accounts.DeleteAccountByUsername("router-2fa-status-off")
	})
	session, err := accounts.CreateSession(user.UUID, 3600, "test", "127.0.0.1", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	enabled, validUntil, window := readTwoFactorStatus(t, r, session)
	if enabled || validUntil != 0 || window != 600 {
		t.Fatalf("without 2FA: enabled=%v valid_until=%d window=%d", enabled, validUntil, window)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/2fa/status", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status returned %d, want 401", w.Code)
	}
}

// newFullTestEngine 挂上身份识别与 CSRF 中间件以及公开、管理员路由（与 runtime.go 顺序一致）。
func newFullTestEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(api.IdentityMiddleware(), api.CSRFProtection())
	registerPublicRoutes(r)
	registerAdminRoutes(r)
	return r
}

func TestThemeSetAcceptsQueryAndJSONBody(t *testing.T) {
	r := newFullTestEngine()
	_, session := routerTestSession(t, "router-theme-set")
	if err := accounts.MarkSessionMFAVerified(session); err != nil {
		t.Fatalf("mark verified: %v", err)
	}

	send := func(target, body, site string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Sec-Fetch-Site", site)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: session})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if w := send("/api/admin/theme/set?theme=default", "", "same-origin"); w.Code != http.StatusOK {
		t.Fatalf("theme from query returned %d: %s", w.Code, w.Body.String())
	}
	if w := send("/api/admin/theme/set", `{"theme":"default"}`, "same-origin"); w.Code != http.StatusOK {
		t.Fatalf("theme from JSON body returned %d: %s", w.Code, w.Body.String())
	}
	if w := send("/api/admin/theme/set", `{}`, "same-origin"); w.Code != http.StatusBadRequest {
		t.Fatalf("missing theme returned %d: %s", w.Code, w.Body.String())
	}
	// 路由级 CSRF：cookie 会话的跨站写请求被拒绝。
	if w := send("/api/admin/theme/set?theme=default", "", "cross-site"); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site theme change returned %d, want 403", w.Code)
	}
}

func TestLogoutViaPOST(t *testing.T) {
	r := newFullTestEngine()
	_, session := routerTestSession(t, "router-logout")

	req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: session})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("POST /api/logout returned %d: %s", w.Code, w.Body.String())
	}
	if _, err := accounts.GetSession(session); err == nil {
		t.Fatal("session survived logout")
	}
}

func TestAnonymousCrossOriginRPCNotBlockedByCSRF(t *testing.T) {
	r := newFullTestEngine()
	req := httptest.NewRequest(http.MethodPost, "/api/rpc2", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"public:getVersion"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://third-party.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusForbidden {
		t.Fatalf("anonymous cross-origin RPC was rejected: %s", w.Body.String())
	}
}

// 备份下载与节点文件上传都能绕过 step-up（备份含 2FA 密钥，上传可写 crontab），
// 必须挂敏感操作二次验证。
func TestSensitiveRESTRoutesRequireStepUp(t *testing.T) {
	// 备份接口会在工作目录下写 ./data/backup，切到临时目录避免污染仓库。
	t.Chdir(t.TempDir())
	r := newAdminTestEngine()

	routes := []struct {
		name, method, target string
	}{
		{name: "backup download", method: http.MethodGet, target: "/api/admin/download/backup"},
		{name: "node file upload", method: http.MethodPost, target: "/api/admin/client/00000000-0000-0000-0000-000000000001/file/upload?operation=not-a-real-operation"},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			_, session := routerTestSession(t, "router-stepup-"+strings.ReplaceAll(route.name, " ", "-"))

			w := serveWithSession(r, route.method, route.target, "", session)
			if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "2FA code is required") {
				t.Fatalf("without step-up: status=%d body=%s, want 401 2FA code is required", w.Code, w.Body.String())
			}

			if err := accounts.MarkSessionMFAVerified(session); err != nil {
				t.Fatalf("mark verified: %v", err)
			}
			w = serveWithSession(r, route.method, route.target, "", session)
			if w.Code == http.StatusUnauthorized || strings.Contains(w.Body.String(), "2FA code is required") {
				t.Fatalf("fresh step-up window was rejected: status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
