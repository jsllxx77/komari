package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/utils"
	"github.com/komari-monitor/komari/web/api"
)

// oauth.go
// 外部账号绑定/解绑：绑定走 302 重定向，保留为 REST handler（不走 RPC 桥）。
// OIDC provider 配置的 get/set 已迁移为 RPC2 方法（见 web/rpc/jsonrpc/admin.provider.go）。

func BindingExternalAccount(c *gin.Context) {
	session, _ := c.Cookie("session_token")
	user, err := accounts.GetUserBySession(session)
	if err != nil {
		api.RespondError(c, 500, "No user found: "+err.Error())
		return
	}
	// 这个 cookie 只承载"本次授权是绑定"的意图，真正的账号归属记录在服务端
	// （见 web/api/public/oauth_state.go）。用 SameSite=Strict + 短有效期 +
	// HttpOnly，避免跨站请求把它带到别人的授权流程里。
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "binding_external_account",
		Value:    user.UUID,
		Path:     "/",
		MaxAge:   120,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   utils.GetScheme(c) == "https",
	})
	c.Redirect(302, "/api/oauth")
}

func UnbindExternalAccount(c *gin.Context) {
	session, _ := c.Cookie("session_token")
	user, err := accounts.GetUserBySession(session)
	if err != nil {
		api.RespondError(c, 500, "No user found: "+err.Error())
		return
	}
	if err := accounts.UnbindExternalAccount(user.UUID); err != nil {
		api.RespondError(c, 500, "Failed to unbind external account: "+err.Error())
		return
	}
	api.RespondSuccess(c, nil)
}
