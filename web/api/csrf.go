package api

// csrf.go
// F-07：会话 cookie 是 SameSite=Lax，跨站顶级导航（<a href>、window.open）的
// GET 请求会带上它，而 Lax 也挡不住同站来源（同一注册域下被控制的其他子域）。
// 这里补两层防护：
//
//  1. CSRFProtection：对所有"非安全方法"（GET/HEAD/OPTIONS 以外）且使用 cookie
//     认证的请求做来源校验。API Key / agent token 请求不经浏览器 cookie，跳过。
//  2. LegacyStateChangingGet：给过渡期仍保留的会改状态的 GET 路由做来源校验。

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/pkg/rpc"
	"github.com/komari-monitor/komari/web/security"
)

// CSRFProtection 拒绝来自其他站点的、依赖会话 cookie 的写请求。
//
// 判定规则（与 CORS 白名单共用配置）：
//   - 有 Origin 时：必须与 Host 相同，或在 CORS 白名单中精确命中；
//     仅靠 "*" 通配符命中的不算（通配符不放行凭据，见 F-23）。
//   - 没有 Origin 时看 Sec-Fetch-Site：只允许 same-origin / none；
//     两者都没有（老客户端、curl）放行，因为它们不依赖 cookie。
//   - API Key 与 agent token 认证的请求直接放行。
func CSRFProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}
		if p := GetPrincipal(c); p != nil {
			if p.Type == rpc.PrincipalAPIKey || p.Type == rpc.PrincipalAgent {
				c.Next()
				return
			}
		}
		allowlist, _ := config.GetAs[string](config.CorsAllowedOriginsKey, "")
		if !isSameOriginMutation(c.Request, allowlist) {
			RespondError(c, http.StatusForbidden, "Cross-site request rejected.")
			c.Abort()
			return
		}
		c.Next()
	}
}

// LegacyStateChangingGet 是过渡期保护：仍以 GET 暴露的会改状态路由
// （/api/logout、/api/admin/theme/set、/api/admin/oauth2/bind）要求
// Sec-Fetch-Site 为 same-origin 或 none；缺失该头（老客户端/curl）时放行。
func LegacyStateChangingGet() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}
		site := strings.ToLower(strings.TrimSpace(c.GetHeader("Sec-Fetch-Site")))
		switch site {
		case "", "same-origin", "none":
			c.Next()
		default:
			RespondError(c, http.StatusForbidden, "Cross-site request rejected.")
			c.Abort()
		}
	}
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// isSameOriginMutation 判断一个写请求是否来自本站/受信来源。
func isSameOriginMutation(r *http.Request, allowlist string) bool {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		if security.OriginMatchesHost(origin, r.Host) {
			return true
		}
		matched, viaWildcard := security.OriginInAllowlist(origin, allowlist)
		return matched && !viaWildcard
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "", "same-origin", "none":
		return true
	default:
		return false
	}
}
