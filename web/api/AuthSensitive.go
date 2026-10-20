package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/pkg/rpc"
	logger "github.com/komari-monitor/komari/utils/log"
)

// max2FACodeBodyPeek 是查找验证码时允许预读的请求体上限。
// 该中间件在需要敏感操作二次验证的请求上运行，不能无上限地缓冲请求体。
const max2FACodeBodyPeek = 64 << 10

// mfaStepUpWindow 是"近期已通过 2FA"的有效期：窗口内调用敏感方法不再要求验证码。
const mfaStepUpWindow = 10 * time.Minute

// allowQueryTwoFactorCode 控制是否仍从 URL 查询参数读取 2FA 验证码。
// 从 URL 取码会把验证码写进反代日志和 Referer，下个版本会移除；
// 当前保留是为了兼容尚未适配的前端，改成 false 即立即关闭。
var allowQueryTwoFactorCode = true

var query2FADeprecationOnce sync.Once

func RequireSensitive2FA() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, isAPIKey := c.Get("api_key")
		uuidRaw, _ := c.Get("uuid")
		uuid, _ := uuidRaw.(string)

		// 只有账号确实启用了 2FA 时才会去提取验证码：提取可能要读请求体，
		// 未启用 2FA 的账号不应该为此付出代价。
		err := VerifySensitive2FAFor(uuid, sessionToken(c), isAPIKey, func() string { return get2FACode(c) })
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, accounts.ErrTooMany2FAAttempts) {
				status = http.StatusTooManyRequests
			}
			RespondError(c, status, err.Error())
			c.Abort()
			return
		}
		// 标记本请求已通过敏感操作校验，避免下游（RPC 边界）重复校验。
		c.Set("sensitive_2fa_verified", true)
		c.Next()
	}
}

// VerifySensitive2FAFor 是传输无关的敏感操作二次验证入口。
// API Key 豁免；未启用 2FA 的账号放行；其余需要"近期通过过 2FA"或本次请求带有效验证码。
// code 是延迟提取函数：只有需要验证码时才会被调用。
func VerifySensitive2FAFor(userUUID, sessionToken string, isAPIKey bool, code func() string) error {
	if isAPIKey {
		return nil
	}
	if userUUID == "" {
		return err2FARequired()
	}
	user, err := accounts.GetUserByUUID(userUUID)
	if err != nil {
		return err
	}
	if user.TwoFactor == "" {
		return nil
	}

	// step-up：登录时已经验过 TOTP 的会话在窗口内不再重复要求验证码。
	if sessionToken != "" {
		if verifiedAt, ok, err := accounts.SessionMFAVerifiedAt(sessionToken); err == nil && ok {
			if time.Since(verifiedAt) < mfaStepUpWindow {
				return nil
			}
		}
	}

	codeValue := ""
	if code != nil {
		codeValue = code()
	}
	if codeValue == "" {
		return err2FARequired()
	}
	ok, verifyErr := accounts.Verify2FaStrict(userUUID, codeValue)
	if verifyErr != nil {
		return verifyErr
	}
	if !ok {
		return err2FAInvalid()
	}
	// 本次输入有效：把会话在窗口内标记为已通过，后续敏感操作不再要求验证码。
	if sessionToken != "" {
		_ = accounts.MarkSessionMFAVerified(sessionToken)
	}
	return nil
}

// sessionToken 读取当前请求的会话令牌（cookie 认证场景）。
func sessionToken(c *gin.Context) string {
	session, err := c.Cookie("session_token")
	if err != nil {
		return ""
	}
	return session
}

// VerifySensitive2FACore 传输无关的 2FA 校验核心。
// 输入原始值:userUUID、会话令牌、2FA code、是否为 API Key。
func VerifySensitive2FACore(userUUID, sessionToken, code string, isAPIKey bool) error {
	return VerifySensitive2FAFor(userUUID, sessionToken, isAPIKey, func() string { return code })
}

// VerifySensitive2FA gin 适配层:从 gin.Context 提取参数后委托核心校验。
func VerifySensitive2FA(c *gin.Context) error {
	_, isAPIKey := c.Get("api_key")
	uuidRaw, _ := c.Get("uuid")
	uuid, _ := uuidRaw.(string)
	return VerifySensitive2FAFor(uuid, sessionToken(c), isAPIKey, func() string { return get2FACode(c) })
}

// TwoFactorCodeFromRequest 从请求头或请求体读取验证码，不接受查询参数。
// 供不经过敏感操作中间件的接口（例如启用 2FA）使用。
func TwoFactorCodeFromRequest(c *gin.Context) string {
	if code := c.GetHeader("X-2FA-Code"); code != "" {
		return code
	}
	if code := c.GetHeader("X-Two-Factor-Code"); code != "" {
		return code
	}
	return twoFactorCodeFromBody(c)
}

func get2FACode(c *gin.Context) string {
	if code, ok := c.Get("2fa_code"); ok {
		if codeString, ok := code.(string); ok && codeString != "" {
			return codeString
		}
	}
	if code := c.GetHeader("X-2FA-Code"); code != "" {
		return code
	}
	if code := c.GetHeader("X-Two-Factor-Code"); code != "" {
		return code
	}
	if allowQueryTwoFactorCode {
		for _, key := range []string{"2fa_code", "two_factor_code", "otp"} {
			if code := c.Query(key); code != "" {
				query2FADeprecationOnce.Do(func() {
					logger.Warnf("auth", "2FA code from the URL query is deprecated and will be rejected in a future release; send X-2FA-Code or 2fa_code in the body instead")
				})
				return code
			}
		}
	}
	return twoFactorCodeFromBody(c)
}

// twoFactorCodeFromBody 从 JSON 请求体中读取验证码。
// 预读有上限的前缀，再把未读部分拼回去，保证下游 handler 仍能读到完整请求体。
func twoFactorCodeFromBody(c *gin.Context) string {
	if c.Request.Body == nil || c.Request.Method == http.MethodGet {
		return ""
	}
	original := c.Request.Body
	prefix, err := io.ReadAll(io.LimitReader(original, max2FACodeBodyPeek+1))
	c.Request.Body = prefixedBody{Reader: io.MultiReader(bytes.NewReader(prefix), original), Closer: original}
	if err != nil || len(prefix) == 0 || len(prefix) > max2FACodeBodyPeek {
		return ""
	}
	var body map[string]interface{}
	if err := json.Unmarshal(prefix, &body); err != nil {
		return ""
	}
	for _, key := range []string{"2fa_code", "two_factor_code", "otp"} {
		if value, ok := body[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

// RequireSensitive2FAFromContext 供 handler 内部对"按内容决定是否敏感"的接口
// 做二次校验（例如只修改了安全相关配置项的设置保存）。code 为本次请求带来的验证码。
func RequireSensitive2FAFromContext(ctx context.Context, code string) error {
	meta := rpc.MetaFromContext(ctx)
	if meta == nil || meta.Principal == nil {
		return errors.New("missing caller identity")
	}
	return VerifySensitive2FACore(meta.Principal.UserUUID, meta.SessionToken, code, meta.Principal.IsAPIKey)
}

func err2FARequired() error {
	return &sensitive2FAError{"2FA code is required"}
}

func err2FAInvalid() error {
	return &sensitive2FAError{"Invalid 2FA code"}
}

type sensitive2FAError struct {
	message string
}

func (e *sensitive2FAError) Error() string {
	return e.message
}
