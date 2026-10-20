package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	logger "github.com/komari-monitor/komari/utils/log"
)

// max2FACodeBodyPeek 是查找验证码时允许预读的请求体上限。
// 该中间件在需要敏感操作二次验证的请求上运行，不能无上限地缓冲请求体。
const max2FACodeBodyPeek = 64 << 10

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
		err := VerifySensitive2FAFor(uuid, isAPIKey, func() string { return get2FACode(c) })
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
// API Key 豁免；未启用 2FA 的账号放行；其余需要有效的一次性验证码。
// code 是延迟提取函数：只有账号启用了 2FA 时才会被调用。
func VerifySensitive2FAFor(userUUID string, isAPIKey bool, code func() string) error {
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
	return nil
}

// VerifySensitive2FACore 传输无关的 2FA 校验核心。
// 输入原始值:userUUID、2FA code、是否为 API Key。
func VerifySensitive2FACore(userUUID, code string, isAPIKey bool) error {
	return VerifySensitive2FAFor(userUUID, isAPIKey, func() string { return code })
}

// VerifySensitive2FA gin 适配层:从 gin.Context 提取参数后委托核心校验。
func VerifySensitive2FA(c *gin.Context) error {
	_, isAPIKey := c.Get("api_key")
	uuidRaw, _ := c.Get("uuid")
	uuid, _ := uuidRaw.(string)
	return VerifySensitive2FAFor(uuid, isAPIKey, func() string { return get2FACode(c) })
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
	if c.Request.Body == nil || c.Request.Method == http.MethodGet {
		return ""
	}
	// 预读有上限的前缀，再把未读部分拼回去，保证下游 handler 仍能读到完整请求体。
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
