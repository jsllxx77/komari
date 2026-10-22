package public

// oauth_2fa.go
// OAuth 登录的第二因子。管理员开启 TOTP 后，OAuth 回调不再直接发会话，
// 而是先发一个一次性的“待验证”令牌（只存在服务端），由这里完成验证码校验。
// 页面由服务端直接返回，因为前端源码不在本仓库。

import (
	"errors"
	"html"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/utils"
	"github.com/komari-monitor/komari/web/api"
	"github.com/patrickmn/go-cache"
)

const (
	oauth2FACookie      = "oauth_2fa_pending"
	oauth2FAPagePath    = "/api/oauth/2fa"
	oauth2FAMaxAttempts = 5
)

// pendingOAuthLogin 是等待第二因子的登录尝试。它只存在服务端，
// cookie 里只有一个随机 ID，泄露 cookie 也拿不到账号信息。
type pendingOAuthLogin struct {
	UserUUID string
	Attempts int
}

var (
	oauth2FAPending       = cache.New(5*time.Minute, 10*time.Minute)
	oauth2FAPendingMutex  sync.Mutex
	oauth2FASessionMethod = "oauth+2fa"
)

const oauth2FAHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Two-factor authentication</title>
</head>
<body>
<h1>Two-factor authentication</h1>
<p>%s</p>
<form method="post" action="` + oauth2FAPagePath + `">
<input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="8" required autofocus>
<button type="submit">Verify</button>
</form>
</body>
</html>
`

// startPendingOAuth2FA 为已通过 OAuth 认证的账号创建一次待验证登录，
// 并把随机令牌通过 HttpOnly cookie 交给浏览器。
func startPendingOAuth2FA(c *gin.Context, userUUID string) {
	token := utils.GenerateRandomString(32)
	if token == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to start 2FA verification"})
		return
	}
	oauth2FAPendingMutex.Lock()
	oauth2FAPending.Set(token, &pendingOAuthLogin{UserUUID: userUUID}, cache.DefaultExpiration)
	oauth2FAPendingMutex.Unlock()

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     oauth2FACookie,
		Value:    token,
		Path:     "/api/oauth",
		MaxAge:   int((5 * time.Minute).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   utils.GetScheme(c) == "https",
	})
	auditlog.Log(c.ClientIP(), userUUID, "OAuth login requires 2FA", "login")
	c.Redirect(http.StatusFound, oauth2FAPagePath)
}

// oauth2FAVerify 是第二步实际使用的校验函数，测试会替换它来统计校验次数。
var oauth2FAVerify = accounts.Verify2FaStrict

// reservePendingOAuthAttempt 在同一把锁里取出待验证记录并预占一次尝试。
// 名额用完的令牌直接作废并返回 exhausted=true：先占名额再校验，并发提交
// 同一个令牌最多只会校验 oauth2FAMaxAttempts 次。
func reservePendingOAuthAttempt(token string) (record *pendingOAuthLogin, exhausted bool) {
	oauth2FAPendingMutex.Lock()
	defer oauth2FAPendingMutex.Unlock()
	record = takePendingOAuthLogin(token)
	if record == nil {
		return nil, false
	}
	if record.Attempts >= oauth2FAMaxAttempts {
		oauth2FAPending.Delete(token)
		return nil, true
	}
	record.Attempts++
	return record, false
}

// consumePendingOAuthLogin 原子地删除待验证记录，记录仍存在时返回 true。
func consumePendingOAuthLogin(token string) bool {
	oauth2FAPendingMutex.Lock()
	defer oauth2FAPendingMutex.Unlock()
	if takePendingOAuthLogin(token) == nil {
		return false
	}
	oauth2FAPending.Delete(token)
	return true
}

// takePendingOAuthLogin 查找待验证记录（不修改）。
func takePendingOAuthLogin(token string) *pendingOAuthLogin {
	if token == "" {
		return nil
	}
	value, ok := oauth2FAPending.Get(token)
	if !ok {
		return nil
	}
	record, ok := value.(*pendingOAuthLogin)
	if !ok {
		return nil
	}
	return record
}

func dropPendingOAuthLogin(c *gin.Context, token string) {
	if token != "" {
		oauth2FAPendingMutex.Lock()
		oauth2FAPending.Delete(token)
		oauth2FAPendingMutex.Unlock()
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     oauth2FACookie,
		Value:    "",
		Path:     "/api/oauth",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   utils.GetScheme(c) == "https",
	})
}

func renderOAuth2FAForm(c *gin.Context, status int, message string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	c.Header("X-Content-Type-Options", "nosniff")
	c.String(status, oauth2FAHTML, html.EscapeString(message))
}

// OAuth2FAForm 返回最简的验证码输入页。
func OAuth2FAForm(c *gin.Context) {
	token, _ := c.Cookie(oauth2FACookie)
	if takePendingOAuthLogin(token) == nil {
		dropPendingOAuthLogin(c, token)
		c.Redirect(http.StatusFound, "/")
		return
	}
	renderOAuth2FAForm(c, http.StatusOK, "Enter the 6-digit code from your authenticator app.")
}

// OAuth2FASubmit 校验验证码，成功后才创建会话。
func OAuth2FASubmit(c *gin.Context) {
	token, _ := c.Cookie(oauth2FACookie)
	record, exhausted := reservePendingOAuthAttempt(token)
	if exhausted {
		dropPendingOAuthLogin(c, token)
		renderOAuth2FAForm(c, http.StatusBadRequest, "Too many failed attempts. Please sign in again.")
		return
	}
	if record == nil {
		dropPendingOAuthLogin(c, token)
		renderOAuth2FAForm(c, http.StatusBadRequest, "This login attempt has expired. Please sign in again.")
		return
	}

	code := c.PostForm("code")
	if code == "" {
		code = api.TwoFactorCodeFromRequest(c)
	}

	ok, err := oauth2FAVerify(record.UserUUID, code)
	if errors.Is(err, accounts.ErrTooMany2FAAttempts) {
		dropPendingOAuthLogin(c, token)
		auditlog.Log(c.ClientIP(), record.UserUUID, "OAuth 2FA blocked: too many attempts", "warn")
		renderOAuth2FAForm(c, http.StatusTooManyRequests, "Too many failed attempts. Please sign in again later.")
		return
	}
	if err != nil || !ok {
		// 本次尝试已在 reservePendingOAuthAttempt 里计入。
		oauth2FAPendingMutex.Lock()
		attempts := record.Attempts
		oauth2FAPendingMutex.Unlock()
		auditlog.Log(c.ClientIP(), record.UserUUID, "OAuth 2FA failed", "warn")
		if attempts >= oauth2FAMaxAttempts {
			dropPendingOAuthLogin(c, token)
			renderOAuth2FAForm(c, http.StatusBadRequest, "Too many failed attempts. Please sign in again.")
			return
		}
		renderOAuth2FAForm(c, http.StatusBadRequest, "Invalid 2FA code.")
		return
	}

	// 令牌只能换一次会话：并发提交时只有第一个成功取走令牌的请求能登录。
	if !consumePendingOAuthLogin(token) {
		dropPendingOAuthLogin(c, token)
		renderOAuth2FAForm(c, http.StatusBadRequest, "This login attempt has expired. Please sign in again.")
		return
	}
	dropPendingOAuthLogin(c, token)

	session, err := accounts.CreateSession(record.UserUUID, sessionCookieMaxAge, c.Request.UserAgent(), c.ClientIP(), oauth2FASessionMethod)
	if err != nil {
		renderOAuth2FAForm(c, http.StatusInternalServerError, "Failed to create session.")
		return
	}
	if err := accounts.MarkSessionMFAVerified(session); err != nil {
		auditlog.Log(c.ClientIP(), record.UserUUID, "failed to record 2FA step-up state: "+err.Error(), "warn")
	}
	setSessionCookie(c, session, sessionCookieMaxAge)
	auditlog.Log(c.ClientIP(), record.UserUUID, "logged in (OAuth+2FA)", "login")
	c.Redirect(http.StatusFound, "/admin/dashboard")
}
