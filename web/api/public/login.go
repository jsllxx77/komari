package public

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/utils"
	logger "github.com/komari-monitor/komari/utils/log"
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

// loginNow 可在测试中替换，便于控制限流窗口。
var loginNow = time.Now

// loginFailureSleep 抽成变量，测试可替换以避免真的等待。
var loginFailureSleep = func(d time.Duration) {
	if d > 0 {
		time.Sleep(d)
	}
}

// sharedKeyLastWarn 记录上次“共享限流键”告警的 unix 秒，0 表示尚未告警。
var sharedKeyLastWarn atomic.Int64

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
	warnSharedLimiterKey(clientIP, c.Request.RemoteAddr)

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

	now := loginNow()
	allowed, retryAfter, res := loginAttempts.Begin(clientIP, data.Username, now)
	if !allowed {
		c.Header("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
		api.RespondError(c, http.StatusTooManyRequests, "Too many failed login attempts, please try again later")
		return
	}

	uuid, success := accounts.CheckPassword(data.Username, data.Password)
	if !success {
		recordLoginFailure(res, clientIP, data.Username, now)
		api.RespondError(c, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	// 2FA
	user, err := accounts.GetUserByUUID(uuid)
	if err != nil {
		loginAttempts.Cancel(res)
		api.RespondError(c, http.StatusInternalServerError, "Failed to load account")
		return
	}
	twoFAVerified := false
	if user.TwoFactor != "" { // 开启了2FA
		if data.TwoFa == "" {
			loginAttempts.Cancel(res)
			api.RespondError(c, http.StatusUnauthorized, "2FA code is required")
			return
		}
		ok, verifyErr := accounts.Verify2FaStrict(uuid, data.TwoFa)
		if errors.Is(verifyErr, accounts.ErrTooMany2FAAttempts) {
			loginAttempts.Cancel(res)
			auditlog.Log(clientIP, uuid, "password login blocked: too many 2FA attempts", "warn")
			c.Header("Retry-After", "300")
			api.RespondError(c, http.StatusTooManyRequests, accounts.ErrTooMany2FAAttempts.Error())
			return
		}
		if verifyErr != nil || !ok {
			recordLoginFailure(res, clientIP, data.Username, now)
			api.RespondError(c, http.StatusUnauthorized, "Invalid 2FA code")
			return
		}
		twoFAVerified = true
	}
	// Create session
	session, err := accounts.CreateSession(uuid, sessionCookieMaxAge, c.Request.UserAgent(), c.ClientIP(), "password")
	if err != nil {
		loginAttempts.Cancel(res)
		api.RespondError(c, http.StatusInternalServerError, "Failed to create session: "+err.Error())
		return
	}
	if twoFAVerified {
		// 登录时刚验过 TOTP：会话在 step-up 窗口内不再要求重复输入验证码。
		if err := accounts.MarkSessionMFAVerified(session); err != nil {
			auditlog.Log(clientIP, uuid, "failed to record 2FA step-up state: "+err.Error(), "warn")
		}
	}
	loginAttempts.ConfirmSuccess(res, now)
	setSessionCookie(c, session, sessionCookieMaxAge)
	auditlog.Log(clientIP, uuid, "logged in (password)", "login")
	// 只通过 HttpOnly cookie 下发会话，响应体不再包含明文 session_token。
	api.RespondSuccess(c, nil)
}

// recordLoginFailure 确认一次失败登录，必要时写入审计日志，并按用户名维度的
// 失败次数在响应前附加延迟。
func recordLoginFailure(res *loginReservation, clientIP, username string, now time.Time) {
	if loginAttempts.ConfirmFailure(res, now) {
		auditlog.Log(clientIP, "", fmt.Sprintf("password login blocked for %s after %d failed attempts", loginFailureWindow, loginFailureLimit), "warn")
	}
	loginFailureSleep(loginAttempts.FailureDelay(username, now))
}

// warnSharedLimiterKey 在 ClientIP 退化为回环地址或直接对端地址（说明
// X-Forwarded-For 没有传过来，所有客户端共用一个限流键）时告警，每小时最多一次。
func warnSharedLimiterKey(clientIP, remoteAddr string) {
	sharedKeyWarnOnce(clientIP, remoteAddr, time.Now(), func(message string) {
		logger.Warnf("login", "%s", message)
	})
}

func sharedKeyWarnOnce(clientIP, remoteAddr string, now time.Time, warn func(string)) bool {
	if !sharedLimiterKey(clientIP, remoteAddr) {
		return false
	}
	nowUnix := now.Unix()
	for {
		last := sharedKeyLastWarn.Load()
		if last != 0 && nowUnix-last < int64(time.Hour/time.Second) {
			return false
		}
		if sharedKeyLastWarn.CompareAndSwap(last, nowUnix) {
			break
		}
	}
	if warn != nil {
		warn(fmt.Sprintf("login rate limiter key is shared: ClientIP %q equals the peer %q and X-Forwarded-For is missing; if this peer is a reverse proxy, list it in --trusted-proxies and make it send X-Forwarded-For", clientIP, remoteAddr))
	}
	return true
}

// sharedLimiterKey 判断 ClientIP 是否说明限流键被共享：解析结果是回环地址，
// 或者就是直接对端自身且该对端为回环/私有地址（通常是没传 XFF 的反向代理）。
func sharedLimiterKey(clientIP, remoteAddr string) bool {
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.Trim(strings.TrimSpace(remoteAddr), "[]")
	}
	peer := net.ParseIP(host)
	if peer == nil || !peer.Equal(ip) {
		return false
	}
	return peer.IsPrivate() || peer.IsLoopback()
}

func Logout(c *gin.Context) {
	session, _ := c.Cookie("session_token")
	accounts.DeleteSession(session)
	setSessionCookie(c, "", -1)
	auditlog.Log(c.ClientIP(), "", "logged out", "logout")
	c.Redirect(302, "/")
}
