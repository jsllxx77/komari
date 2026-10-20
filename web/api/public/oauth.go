package public

import (
	"crypto/subtle"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/utils"
	"github.com/komari-monitor/komari/web/oauth"
)

// /api/oauth
func OAuth(c *gin.Context) {
	OAuthEnabled, _ := config.GetAs[bool](config.OAuthEnabledKey, false)
	if !OAuthEnabled {
		c.JSON(403, gin.H{"status": "error", "error": "OAuth is not enabled"})
		return
	}

	authURL, state := oauth.CurrentProvider().GetAuthorizationURL(utils.GetCallbackURL(c))
	if state == "" || authURL == "" {
		c.JSON(502, gin.H{"status": "error", "error": "Failed to start OAuth flow"})
		return
	}

	// 默认是登录；只有带着"刚通过校验的本人会话"的绑定请求才会被记成绑定。
	record := oauthStateRecord{Kind: oauthIntentLogin}
	if bindUUID, err := c.Cookie(bindingIntentCookie); err == nil && bindUUID != "" {
		session, _ := c.Cookie("session_token")
		if user, err := accounts.GetUserBySession(session); err == nil && user.UUID == bindUUID {
			record = oauthStateRecord{Kind: oauthIntentBind, UserUUID: bindUUID}
		}
		// 意图只对这一次授权有效。
		c.SetCookie(bindingIntentCookie, "", -1, "/", "", utils.GetScheme(c) == "https", true)
	}
	rememberOAuthState(state, record)

	c.SetCookie("oauth_state", state, 3600, "/", "", utils.GetScheme(c) == "https", true)

	c.Redirect(302, authURL)
}

// oauthCallbackState 从回调里取出与 cookie 中比对用的 state。
// QQ 走聚合登录平台，state 不在它回传的 url 里，所以我们把它放进自己的
// redirect_uri（?ks=...），由平台原样带回。
func oauthCallbackState(c *gin.Context, providerName string) string {
	if providerName == "qq" {
		return c.Query("ks")
	}
	return c.Query("state")
}

// /api/oauth_callback
func OAuthCallback(c *gin.Context) {
	if enabled, _ := config.GetAs[bool](config.OAuthEnabledKey, false); !enabled {
		c.JSON(403, gin.H{"status": "error", "error": "OAuth is not enabled"})
		return
	}

	// 验证 state 防止 CSRF：cookie 里的值必须与本次回调带回的值一致。
	state, _ := c.Cookie("oauth_state")
	c.SetCookie("oauth_state", "", -1, "/", "", utils.GetScheme(c) == "https", true)

	providerName := oauth.CurrentProvider().GetName()
	returnedState := oauthCallbackState(c, providerName)
	if state == "" || returnedState == "" || subtle.ConstantTimeCompare([]byte(state), []byte(returnedState)) != 1 {
		c.JSON(400, gin.H{"status": "error", "error": "Invalid state"})
		return
	}

	// 取出服务端记录的意图：没有记录说明不是我们发起的授权，直接拒绝。
	intent, ok := takeOAuthState(state)
	if !ok {
		c.JSON(400, gin.H{"status": "error", "error": "Invalid state"})
		return
	}

	queries := make(map[string]string)
	for key, values := range c.Request.URL.Query() {
		if len(values) > 0 {
			queries[key] = values[0]
		}
	}
	oidcUser, err := oauth.CurrentProvider().OnCallback(c, state, queries, utils.GetCallbackURL(c))
	if err != nil {
		c.JSON(500, gin.H{"status": "error", "error": "Failed to get user info: " + err.Error()})
		return
	}

	// ID作为SSO ID
	sso_id := fmt.Sprintf("%s_%s", oauth.CurrentProvider().GetName(), oidcUser.UserId)

	// 绑定流程：意图来自服务端记录，并且当前会话必须仍是这个账号。
	if intent.Kind == oauthIntentBind {
		session, _ := c.Cookie("session_token")
		account, err := accounts.GetUserBySession(session)
		if err != nil || account.UUID != intent.UserUUID {
			c.JSON(400, gin.H{"status": "error", "message": "Binding failed"})
			return
		}
		if err := accounts.BindingExternalAccount(account.UUID, sso_id); err != nil {
			c.JSON(500, gin.H{"status": "error", "message": "Binding failed"})
			return
		}
		auditlog.Log(c.ClientIP(), account.UUID, "bound external account (OAuth)"+fmt.Sprintf(",sso_id: %s", sso_id), "login")
		c.Redirect(302, "/admin/dashboard")
		return
	}

	// 尝试获取用户
	user, err := accounts.GetUserBySSO(sso_id)
	if err != nil {
		c.JSON(401, gin.H{
			"status":  "error",
			"message": "please log in and bind your external account first.",
		})
		return
	}

	// 启用 TOTP 的账号必须再走一步验证码，否则第三方账号被控制就等于绕过了 2FA。
	if user.TwoFactor != "" {
		startPendingOAuth2FA(c, user.UUID)
		return
	}

	// 创建会话
	session, err := accounts.CreateSession(user.UUID, sessionCookieMaxAge, c.Request.UserAgent(), c.ClientIP(), "oauth")
	if err != nil {
		c.JSON(500, gin.H{"status": "error", "message": err.Error()})
		return
	}

	// 设置cookie并返回
	setSessionCookie(c, session, sessionCookieMaxAge)
	auditlog.Log(c.ClientIP(), user.UUID, "logged in (OAuth)", "login")
	c.Redirect(302, "/admin/dashboard")
}
