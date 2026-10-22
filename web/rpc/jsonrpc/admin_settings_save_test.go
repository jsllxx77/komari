package jsonrpc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/web/api"
	"github.com/pquerna/otp/totp"
)

const settingsTestTOTPSecret = "JBSWY3DPEHPK3PXP"

// settingsTestSession 创建管理员账号与 cookie 会话；with2FA 为 true 时启用 2FA。
func settingsTestSession(t *testing.T, username string, with2FA bool) string {
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
		if err := accounts.Enable2Fa(user.UUID, settingsTestTOTPSecret); err != nil {
			t.Fatalf("enable 2fa: %v", err)
		}
	}
	session, err := accounts.CreateSession(user.UUID, 3600, "test", "127.0.0.1", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return session
}

// postSettings 走真实的 REST 路由桥（身份中间件 + Bind），与前端保存设置的路径一致。
func postSettings(t *testing.T, session, body string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(api.IdentityMiddleware())
	r.POST("/api/admin/settings/", Bind("admin:editSettings"))
	req := httptest.NewRequest(http.MethodPost, "/api/admin/settings/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.AddCookie(&http.Cookie{Name: "session_token", Value: session})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func seedSettings(t *testing.T, values map[string]any) {
	t.Helper()
	dbcore.GetDBInstance() // 确保 config 已绑定数据库
	if err := config.SetMany(values); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
}

func storedString(t *testing.T, key string) string {
	t.Helper()
	value, err := config.GetAs[string](key)
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	return value
}

func TestEditSettingsClearsAPIKeyWithEmptyString(t *testing.T) {
	session := settingsTestSession(t, "settings-clear-key", false)
	seedSettings(t, map[string]any{config.ApiKeyKey: "stored-api-key-123456"})

	// 打码值原样提交：保持原值。
	w := postSettings(t, session, `{"api_key":"****3456","sitename":"Komari"}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("save with masked key returned %d: %s", w.Code, w.Body.String())
	}
	if got := storedString(t, config.ApiKeyKey); got != "stored-api-key-123456" {
		t.Fatalf("masked placeholder overwrote the key: %q", got)
	}

	// 空字符串：清空 API key（前端 sign-on.tsx 的做法）。
	w = postSettings(t, session, `{"api_key":""}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("clearing the key returned %d: %s", w.Code, w.Body.String())
	}
	if got := storedString(t, config.ApiKeyKey); got != "" {
		t.Fatalf("api key was not cleared: %q", got)
	}
}

func TestEditSettingsOnlyChangedSensitiveKeysNeed2FA(t *testing.T) {
	session := settingsTestSession(t, "settings-unchanged", true)
	seedSettings(t, map[string]any{
		config.ApiKeyKey:             "stored-api-key-123456",
		config.CorsAllowedOriginsKey: "https://a.example",
		config.PrivateSiteKey:        false,
	})

	// 整表保存，安全相关键都是原值或打码值：不需要 2FA。
	w := postSettings(t, session, `{"sitename":"Renamed","api_key":"****3456","cors_allowed_origins":"https://a.example","private_site":false}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("saving unchanged sensitive values returned %d: %s", w.Code, w.Body.String())
	}
	if got := storedString(t, config.SitenameKey); got != "Renamed" {
		t.Fatalf("sitename = %q", got)
	}

	// 真的修改了安全相关键：需要 2FA。
	w = postSettings(t, session, `{"cors_allowed_origins":"https://evil.example"}`, nil)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "2FA code is required") {
		t.Fatalf("changing a sensitive key returned %d: %s", w.Code, w.Body.String())
	}
	if got := storedString(t, config.CorsAllowedOriginsKey); got != "https://a.example" {
		t.Fatalf("sensitive key changed without 2FA: %q", got)
	}
	// 清空 API key 同样是敏感修改。
	w = postSettings(t, session, `{"api_key":""}`, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("clearing the api key without 2FA returned %d: %s", w.Code, w.Body.String())
	}
}

func TestEditSettingsAcceptsHeaderCode(t *testing.T) {
	session := settingsTestSession(t, "settings-header-code", true)
	seedSettings(t, map[string]any{config.CorsAllowedOriginsKey: "https://a.example"})

	code, err := totp.GenerateCode(settingsTestTOTPSecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	w := postSettings(t, session, `{"cors_allowed_origins":"https://b.example"}`, map[string]string{"X-2FA-Code": code})
	if w.Code != http.StatusOK {
		t.Fatalf("save with X-2FA-Code returned %d: %s", w.Code, w.Body.String())
	}
	if got := storedString(t, config.CorsAllowedOriginsKey); got != "https://b.example" {
		t.Fatalf("cors_allowed_origins = %q", got)
	}
}

func TestEditSettingsNeverPersistsCodeFields(t *testing.T) {
	for _, key := range twoFactorParamKeys {
		t.Run(key, func(t *testing.T) {
			session := settingsTestSession(t, "settings-code-"+strings.ReplaceAll(key, "_", "-"), true)
			seedSettings(t, map[string]any{config.CorsAllowedOriginsKey: "https://a.example"})
			code, err := totp.GenerateCode(settingsTestTOTPSecret, time.Now().UTC())
			if err != nil {
				t.Fatalf("generate code: %v", err)
			}
			// 另外两个字段带上无关值，确认三个验证码字段都会被删除。
			body := `{"cors_allowed_origins":"https://` + key + `.example","2fa_code":"","two_factor_code":"","otp":"","` + key + `":"` + code + `"}`
			body = strings.Replace(body, `"`+key+`":"",`, "", 1)
			w := postSettings(t, session, body, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("save with %s returned %d: %s", key, w.Code, w.Body.String())
			}
			all, err := config.GetAll()
			if err != nil {
				t.Fatalf("read settings: %v", err)
			}
			for _, codeKey := range twoFactorParamKeys {
				if _, ok := all[codeKey]; ok {
					t.Fatalf("%s was persisted as a setting", codeKey)
				}
			}
		})
	}
}
