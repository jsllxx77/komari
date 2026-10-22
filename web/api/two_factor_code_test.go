package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func enableCodeContext(target, body string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	return c
}

func TestTwoFactorCodeForEnableSources(t *testing.T) {
	cases := []struct {
		name, target, body, header, want string
	}{
		{name: "header wins", target: "/x?code=333333", body: `{"code":"222222"}`, header: "111111", want: "111111"},
		{name: "body 2fa_code", target: "/x?code=333333", body: `{"2fa_code":"222222"}`, want: "222222"},
		{name: "body code", target: "/x?code=333333", body: `{"code":"222222"}`, want: "222222"},
		{name: "query code", target: "/x?code=333333", want: "333333"},
		{name: "query 2fa_code", target: "/x?2fa_code=444444", want: "444444"},
		{name: "nothing", target: "/x", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := enableCodeContext(tc.target, tc.body)
			if tc.header != "" {
				c.Request.Header.Set("X-2FA-Code", tc.header)
			}
			if got := TwoFactorCodeForEnable(c); got != tc.want {
				t.Fatalf("code = %q, want %q", got, tc.want)
			}
			// 下游仍然能读到完整的请求体。
			rest, _ := io.ReadAll(c.Request.Body)
			if string(rest) != tc.body {
				t.Fatalf("body after peek = %q, want %q", rest, tc.body)
			}
		})
	}
}

func TestTwoFactorCodeForEnableQueryFallbackFollowsSwitch(t *testing.T) {
	old := allowQueryTwoFactorCode
	allowQueryTwoFactorCode = false
	t.Cleanup(func() { allowQueryTwoFactorCode = old })

	c := enableCodeContext("/x?code=333333", "")
	if got := TwoFactorCodeForEnable(c); got != "" {
		t.Fatalf("query code accepted with the switch off: %q", got)
	}
	// 只用于启用 2FA 的 code 字段不能被其他入口当成验证码。
	c = enableCodeContext("/x", `{"code":"222222"}`)
	if got := TwoFactorCodeFromRequest(c); got != "" {
		t.Fatalf("TwoFactorCodeFromRequest accepted body field code: %q", got)
	}
}
