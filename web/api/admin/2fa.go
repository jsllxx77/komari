package admin

import (
	"errors"
	"image/png"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/web/api"
	"github.com/patrickmn/go-cache"
)

// pending2FASecrets 保存"已生成但尚未确认"的 2FA 密钥，键为账号 UUID。
// 密钥只存在服务端：以前它放在客户端 cookie 里，拿到会话的人可以自己挑一个
// 密钥、算出对应的 TOTP 覆盖掉已有的 2FA，而户主的改密也不会撤销它。
var pending2FASecrets = cache.New(10*time.Minute, 20*time.Minute)

func Generate2FA(c *gin.Context) {
	uuid := c.GetString("uuid")
	if uuid == "" {
		api.RespondError(c, http.StatusUnauthorized, "Unauthorized.")
		return
	}
	user, err := accounts.GetUserByUUID(uuid)
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, "Failed to load account: "+err.Error())
		return
	}
	if user.TwoFactor != "" {
		// 更换密钥必须先停用：停用需要当前 TOTP，这条路径不能被绕过。
		api.RespondError(c, http.StatusConflict, "2FA is already enabled; disable it before generating a new secret")
		return
	}
	secret, img, err := accounts.Generate2Fa()
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, "Failed to generate 2FA: "+err.Error())
		return
	}
	pending2FASecrets.Set(uuid, secret, cache.DefaultExpiration)
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Type", "image/png")
	c.Writer.WriteHeader(http.StatusOK)
	_ = png.Encode(c.Writer, img)
}

func Enable2FA(c *gin.Context) {
	uuid := c.GetString("uuid")
	if uuid == "" {
		api.RespondError(c, http.StatusUnauthorized, "Unauthorized.")
		return
	}
	value, ok := pending2FASecrets.Get(uuid)
	if !ok {
		api.RespondError(c, http.StatusBadRequest, "2FA setup expired, generate a new secret first")
		return
	}
	secret, _ := value.(string)
	code := api.TwoFactorCodeForEnable(c)
	if code == "" {
		api.RespondError(c, http.StatusBadRequest, "2FA code is required")
		return
	}

	usedStep, valid, err := accounts.Validate2FACodeForSecret(uuid, secret, code)
	if errors.Is(err, accounts.ErrTooMany2FAAttempts) {
		api.RespondError(c, http.StatusTooManyRequests, err.Error())
		return
	}
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, "Failed to verify 2FA code: "+err.Error())
		return
	}
	if !valid {
		api.RespondError(c, http.StatusBadRequest, "Invalid 2FA code")
		return
	}

	// 把启用时用过的时间窗记为已使用，这个验证码不能紧接着再用于登录或敏感操作。
	if err := accounts.Enable2FaIfDisabled(uuid, secret, usedStep); err != nil {
		if errors.Is(err, accounts.ErrTwoFactorAlreadyEnabled) {
			api.RespondError(c, http.StatusConflict, "2FA is already enabled")
			return
		}
		api.RespondError(c, http.StatusInternalServerError, "Failed to enable 2FA: "+err.Error())
		return
	}
	pending2FASecrets.Delete(uuid)

	// 启用 2FA 说明账号可能已被他人使用过，撤销除当前会话外的其他会话。
	if session, err := c.Cookie("session_token"); err == nil && session != "" {
		if err := accounts.DeleteSessionsExcept(uuid, session); err != nil {
			auditlog.Log(c.ClientIP(), uuid, "failed to revoke other sessions after enabling 2FA: "+err.Error(), "warn")
		}
	}
	auditlog.Log(c.ClientIP(), uuid, "enabled 2FA", "security")
	api.RespondSuccess(c, "2FA enabled successfully")
}

func Disable2FA(c *gin.Context) {
	uuid := c.GetString("uuid")
	if uuid == "" {
		api.RespondError(c, http.StatusUnauthorized, "Unauthorized.")
		return
	}
	if err := accounts.Disable2Fa(uuid); err != nil {
		api.RespondError(c, http.StatusInternalServerError, "Failed to disable 2FA: "+err.Error())
		return
	}
	auditlog.Log(c.ClientIP(), uuid, "disabled 2FA", "security")
	api.RespondSuccess(c, "")
}

// twoFactorStatus 是 GET /api/admin/2fa/status 的返回体，字段名是与前端的约定。
type twoFactorStatus struct {
	// Enabled 表示当前账号是否已启用 2FA。
	Enabled bool `json:"enabled"`
	// StepUpValidUntil 是当前 cookie 会话 step-up 窗口的截止时间（Unix 秒），
	// 没有有效窗口或不是 cookie 会话时为 0。
	StepUpValidUntil int64 `json:"step_up_valid_until"`
	// WindowSeconds 是一次 step-up 的有效时长（秒）。
	WindowSeconds int64 `json:"window_seconds"`
}

// Status2FA 返回 2FA 启用状态与当前会话的 step-up 窗口，前端据此决定
// 敏感操作前是否先弹出验证码输入框。
func Status2FA(c *gin.Context) {
	status := twoFactorStatus{WindowSeconds: api.StepUpWindowSeconds()}
	if _, isAPIKey := c.Get("api_key"); !isAPIKey {
		uuid := c.GetString("uuid")
		if uuid == "" {
			api.RespondError(c, http.StatusUnauthorized, "Unauthorized.")
			return
		}
		user, err := accounts.GetUserByUUID(uuid)
		if err != nil {
			api.RespondError(c, http.StatusInternalServerError, "Failed to load account: "+err.Error())
			return
		}
		status.Enabled = user.TwoFactor != ""
		status.StepUpValidUntil = api.StepUpValidUntil(c)
	}
	c.Header("Cache-Control", "no-store")
	api.RespondSuccess(c, status)
}

// Verify2FA 为当前会话开启一段 step-up 窗口：通过后 10 分钟内调用敏感管理
// 接口不再要求验证码，避免每个操作都弹一次。
func Verify2FA(c *gin.Context) {
	uuid := c.GetString("uuid")
	if uuid == "" {
		api.RespondError(c, http.StatusUnauthorized, "Unauthorized.")
		return
	}
	code := api.TwoFactorCodeFromRequest(c)
	if code == "" {
		api.RespondError(c, http.StatusBadRequest, "2FA code is required")
		return
	}
	ok, err := accounts.Verify2FaStrict(uuid, code)
	if errors.Is(err, accounts.ErrTooMany2FAAttempts) {
		api.RespondError(c, http.StatusTooManyRequests, err.Error())
		return
	}
	if errors.Is(err, accounts.Err2FAReplay) {
		// 同一时间窗的验证码已经用过：属于用户输入问题，不是服务端错误。
		auditlog.Log(c.ClientIP(), uuid, "sensitive operation 2FA replay rejected", "warn")
		api.RespondError(c, http.StatusUnauthorized, err.Error())
		return
	}
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, "Failed to verify 2FA code: "+err.Error())
		return
	}
	if !ok {
		auditlog.Log(c.ClientIP(), uuid, "sensitive operation 2FA failed", "warn")
		api.RespondError(c, http.StatusUnauthorized, "Invalid 2FA code")
		return
	}
	session, _ := c.Cookie("session_token")
	if session != "" {
		if err := accounts.MarkSessionMFAVerified(session); err != nil {
			api.RespondError(c, http.StatusInternalServerError, "Failed to update session: "+err.Error())
			return
		}
	}
	api.RespondSuccess(c, "2FA verified")
}
