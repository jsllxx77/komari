package public

// oauth_state.go
// OAuth 流程的服务端状态记录。state 字符串由 provider 生成并发回浏览器，
// 这里把"这次授权是登录还是绑定、绑定到哪个账号"记在服务端，回调时按 state
// 取用并删除。浏览器 cookie 只负责把 state 带回来，不携带任何权限语义。

import (
	"time"

	"github.com/patrickmn/go-cache"
)

const (
	oauthIntentLogin = "login"
	oauthIntentBind  = "bind"

	// bindingIntentCookie 只在 /api/admin/oauth2/bind → /api/oauth 之间传递
	// "本次是绑定"这一意图；真正的账号归属记录在服务端，见 oauthStateRecord。
	bindingIntentCookie = "binding_external_account"
)

type oauthStateRecord struct {
	Kind     string
	UserUUID string
}

var oauthStates = cache.New(10*time.Minute, 5*time.Minute)

func rememberOAuthState(state string, record oauthStateRecord) {
	if state == "" {
		return
	}
	oauthStates.Set(state, record, cache.DefaultExpiration)
}

// takeOAuthState 取出并删除 state 对应的记录；不存在时返回 false。
// state 只能使用一次，重放的回调不会命中记录。
func takeOAuthState(state string) (oauthStateRecord, bool) {
	if state == "" {
		return oauthStateRecord{}, false
	}
	value, ok := oauthStates.Get(state)
	if !ok {
		return oauthStateRecord{}, false
	}
	oauthStates.Delete(state)
	record, ok := value.(oauthStateRecord)
	if !ok {
		return oauthStateRecord{}, false
	}
	return record, true
}
