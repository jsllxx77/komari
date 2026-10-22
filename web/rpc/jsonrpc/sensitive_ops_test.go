package jsonrpc

import (
	"testing"

	"github.com/komari-monitor/komari/pkg/rpc"
)

func TestSensitiveMethodList(t *testing.T) {
	// getSessions 不再返回明文会话令牌，会话页不应因此弹 2FA。
	if rpc.IsSensitive("admin:getSessions") {
		t.Fatal("admin:getSessions must not require step-up any more")
	}
	for _, method := range []string{"admin:exec", "admin:dbExec", "admin:dbQuery", "admin:revealSecret", "admin:getClientToken"} {
		if !rpc.IsSensitive(method) {
			t.Fatalf("%s must stay sensitive", method)
		}
	}
}
