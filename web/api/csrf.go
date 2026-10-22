package api

// csrf.go
// F-07：会话 cookie 是 SameSite=Lax，跨站顶级导航（<a href>、window.open）的
// GET 请求会带上它，而 Lax 也挡不住同站来源（同一注册域下被控制的其他子域）。
// 这里补两层防护：
//
//  1. CSRFProtection：只对使用会话 cookie 的"非安全方法"（GET/HEAD/OPTIONS 以外）
//     请求做来源校验。匿名、API Key、agent token 请求不依赖浏览器 cookie，跳过——
//     否则 CORS 配成 "*" 时第三方匿名调用 /api/rpc2 也会被拦（与 F-23 矛盾）。
//     匿名请求里只有登录入口额外防"登录 CSRF"。
//  2. LegacyStateChangingGet：给过渡期仍保留的会改状态的 GET 路由做来源校验。

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/pkg/rpc"
	"github.com/komari-monitor/komari/web/security"
)

// loginCSRFPaths 是匿名可调用、但成功后会建立会话的入口。
// 跨站页面可以诱导浏览器用攻击者的账号登录（登录 CSRF），这里拒绝明确跨站的提交。
var loginCSRFPaths = map[string]struct{}{
	"/api/login":     {},
	"/api/oauth/2fa": {},
}

// CSRFProtection 拒绝来自其他站点的、依赖会话 cookie 的写请求。
//
// 只对 cookie 会话（PrincipalUser，或请求带了 session_token cookie）检查：
//   - Sec-Fetch-Site 为 same-origin / none：放行（浏览器的判断比 Host 可靠，
//     反代没有透传 Host 时也不会误伤同源请求）；
//   - Sec-Fetch-Site 为 cross-site：拒绝；
//   - Sec-Fetch-Site 为 same-site：Origin 必须在 CORS 白名单中精确命中；
//   - 没有 Sec-Fetch-Site 时看 Origin：与 Host 相同、对端是受信代理时与
//     X-Forwarded-Host 相同、或在 CORS 白名单中精确命中才放行；
//     仅靠 "*" 通配符命中的不算（通配符不放行凭据，见 F-23）；
//   - 两者都没有（老客户端、curl）放行。
//
// 匿名、API Key 与 agent token 请求不检查；匿名请求只对登录入口拒绝
// Sec-Fetch-Site: cross-site。
func CSRFProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}
		p := GetPrincipal(c)
		if p != nil && (p.Type == rpc.PrincipalAPIKey || p.Type == rpc.PrincipalAgent) {
			c.Next()
			return
		}
		if !usesSessionCookie(c, p) {
			if _, ok := loginCSRFPaths[c.Request.URL.Path]; ok && secFetchSite(c.Request) == "cross-site" {
				rejectCrossSite(c)
				return
			}
			c.Next()
			return
		}
		allowlist, _ := config.GetAs[string](config.CorsAllowedOriginsKey, "")
		if !isSameOriginMutation(c.Request, allowlist) {
			rejectCrossSite(c)
			return
		}
		c.Next()
	}
}

func rejectCrossSite(c *gin.Context) {
	RespondError(c, http.StatusForbidden, "Cross-site request rejected.")
	c.Abort()
}

// usesSessionCookie 判断请求是否依赖会话 cookie 认证。
// 带着（可能已失效的）session_token cookie 的请求也按 cookie 会话处理。
func usesSessionCookie(c *gin.Context, p *rpc.Principal) bool {
	if p != nil && p.Type == rpc.PrincipalUser {
		return true
	}
	session, err := c.Cookie("session_token")
	return err == nil && session != ""
}

func secFetchSite(r *http.Request) string {
	return strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
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
		switch secFetchSite(c.Request) {
		case "", "same-origin", "none":
			c.Next()
		default:
			rejectCrossSite(c)
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

// isSameOriginMutation 判断一个 cookie 会话的写请求是否来自本站/受信来源。
func isSameOriginMutation(r *http.Request, allowlist string) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	switch secFetchSite(r) {
	case "same-origin", "none":
		return true
	case "cross-site":
		return false
	case "same-site":
		return originExactlyAllowlisted(origin, allowlist)
	case "":
		// 没有 Sec-Fetch-Site（老浏览器或非浏览器客户端），回退到 Origin 校验。
	default:
		return false
	}
	if origin == "" {
		return true
	}
	if security.OriginMatchesHost(origin, r.Host) {
		return true
	}
	// 反代改写了 Host 时，只有受信代理传来的 X-Forwarded-Host 才可信。
	if security.IsTrustedProxyPeer(r) {
		if forwarded := forwardedHost(r); forwarded != "" && security.OriginMatchesHost(origin, forwarded) {
			return true
		}
	}
	return originExactlyAllowlisted(origin, allowlist)
}

// originExactlyAllowlisted 只认 CORS 白名单里的精确条目，"*" 不算。
func originExactlyAllowlisted(origin, allowlist string) bool {
	if origin == "" {
		return false
	}
	matched, viaWildcard := security.OriginInAllowlist(origin, allowlist)
	return matched && !viaWildcard
}

// forwardedHost 返回 X-Forwarded-Host 的第一个值（离客户端最近的代理写入的原始 Host）。
func forwardedHost(r *http.Request) string {
	value := r.Header.Get("X-Forwarded-Host")
	if value == "" {
		return ""
	}
	first, _, _ := strings.Cut(value, ",")
	return strings.TrimSpace(first)
}
