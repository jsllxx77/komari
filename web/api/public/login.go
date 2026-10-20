package public

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/utils"
	"github.com/komari-monitor/komari/web/api"

	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TwoFa    string `json:"2fa_code"`
}

const sessionCookieMaxAge = 2592000

// maxLoginBodySize 限制登录请求体大小；登录接口无需认证即可访问。
const maxLoginBodySize = 64 << 10

func setSessionCookie(c *gin.Context, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "session_token",
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   utils.GetScheme(c) == "https",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func Login(c *gin.Context) {
	DisablePasswordLogin, _ := config.GetAs[bool](config.DisablePasswordLoginKey, false)
	if DisablePasswordLogin {
		api.RespondError(c, http.StatusForbidden, "Password login is disabled")
		return
	}

	clientIP := c.ClientIP()
	if allowed, retryAfter := loginAttempts.Allow(clientIP, time.Now()); !allowed {
		c.Header("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
		api.RespondError(c, http.StatusTooManyRequests, "Too many failed login attempts, please try again later")
		return
	}

	bodyBytes, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxLoginBodySize))
	if err != nil {
		api.RespondError(c, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}
	var data LoginRequest
	err = json.Unmarshal(bodyBytes, &data)
	if err != nil {
		api.RespondError(c, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}
	if data.Username == "" || data.Password == "" {
		api.RespondError(c, http.StatusBadRequest, "Invalid request body: Username and password are required")
		return
	}

	uuid, success := accounts.CheckPassword(data.Username, data.Password)
	if !success {
		recordLoginFailure(clientIP)
		api.RespondError(c, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	// 2FA
	user, err := accounts.GetUserByUUID(uuid)
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, "Failed to load account")
		return
	}
	twoFAVerified := false
	if user.TwoFactor != "" { // 开启了2FA
		if data.TwoFa == "" {
			api.RespondError(c, http.StatusUnauthorized, "2FA code is required")
			return
		}
		ok, verifyErr := accounts.Verify2FaStrict(uuid, data.TwoFa)
		if errors.Is(verifyErr, accounts.ErrTooMany2FAAttempts) {
			auditlog.Log(clientIP, uuid, "password login blocked: too many 2FA attempts", "warn")
			c.Header("Retry-After", "300")
			api.RespondError(c, http.StatusTooManyRequests, accounts.ErrTooMany2FAAttempts.Error())
			return
		}
		if verifyErr != nil || !ok {
			recordLoginFailure(clientIP)
			api.RespondError(c, http.StatusUnauthorized, "Invalid 2FA code")
			return
		}
		twoFAVerified = true
	}
	// Create session
	session, err := accounts.CreateSession(uuid, sessionCookieMaxAge, c.Request.UserAgent(), c.ClientIP(), "password")
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, "Failed to create session: "+err.Error())
		return
	}
	if twoFAVerified {
		// 登录时刚验过 TOTP：会话在 step-up 窗口内不再要求重复输入验证码。
		if err := accounts.MarkSessionMFAVerified(session); err != nil {
			auditlog.Log(clientIP, uuid, "failed to record 2FA step-up state: "+err.Error(), "warn")
		}
	}
	loginAttempts.Reset(clientIP)
	setSessionCookie(c, session, sessionCookieMaxAge)
	auditlog.Log(clientIP, uuid, "logged in (password)", "login")
	api.RespondSuccess(c, gin.H{"set-cookie": gin.H{"session_token": session}})
}

// recordLoginFailure 记录一次失败登录，并在该地址刚被限流时写入审计日志。
func recordLoginFailure(clientIP string) {
	if loginAttempts.Fail(clientIP, time.Now()) {
		auditlog.Log(clientIP, "", fmt.Sprintf("password login blocked for %s after %d failed attempts", loginFailureWindow, loginFailureLimit), "warn")
	}
}

func Logout(c *gin.Context) {
	session, _ := c.Cookie("session_token")
	accounts.DeleteSession(session)
	setSessionCookie(c, "", -1)
	auditlog.Log(c.ClientIP(), "", "logged out", "logout")
	c.Redirect(302, "/")
}
