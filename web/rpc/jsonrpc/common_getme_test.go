package jsonrpc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/pkg/rpc"
)

// callGetMeAsAgent 以 PrincipalAgent 身份调用 getMe，并把匿名响应结构
// 序列化为 map 便于断言（handler 返回的是匿名 struct，无法直接类型断言）。
func callGetMeAsAgent(t *testing.T, token string) map[string]any {
	t.Helper()

	ctx := rpc.NewContextWithMeta(context.Background(), &rpc.ContextMeta{
		Principal:   rpc.NewAgentPrincipal(""),
		ClientToken: token,
	})

	result, jerr := getMe(ctx, nil)
	if jerr != nil {
		t.Fatalf("getMe returned rpc error: %v", jerr)
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal getMe result: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal getMe result: %v", err)
	}
	return got
}

// TestGetMeAgentReturnsClientUUID 覆盖正常路径：token 能在数据库解析出
// 客户端 UUID 时，响应返回该 UUID（而不是调用者提交的 token 本身）。
func TestGetMeAgentReturnsClientUUID(t *testing.T) {
	const token = "test-getme-agent-token"
	const clientUUID = "test-getme-agent-uuid"

	db := dbcore.GetDBInstance()
	_ = db.Where("uuid = ?", clientUUID).Delete(&models.Client{}).Error
	if err := db.Create(&models.Client{UUID: clientUUID, Token: token, Name: "getme-agent"}).Error; err != nil {
		t.Fatalf("create client fixture: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Where("uuid = ?", clientUUID).Delete(&models.Client{}).Error
	})

	got := callGetMeAsAgent(t, token)

	if loggedIn, _ := got["logged_in"].(bool); !loggedIn {
		t.Fatalf("logged_in = %v, want true", got["logged_in"])
	}
	if got["username"] != "client" {
		t.Fatalf("username = %v, want client", got["username"])
	}
	if got["uuid"] != clientUUID {
		t.Fatalf("uuid = %v, want %q", got["uuid"], clientUUID)
	}
	if got["uuid"] == token {
		t.Fatalf("uuid must not be the submitted token %q", token)
	}
}

// TestGetMeAgentUnknownTokenDoesNotLeakToken 覆盖失败路径：token 无法解析时，
// 响应中的 uuid 必须为空，绝不能回退成调用者提交的 token。
func TestGetMeAgentUnknownTokenDoesNotLeakToken(t *testing.T) {
	const token = "test-getme-unknown-token"

	// 确保该 token 不在库中。
	db := dbcore.GetDBInstance()
	_ = db.Where("token = ?", token).Delete(&models.Client{}).Error

	got := callGetMeAsAgent(t, token)

	uuid, ok := got["uuid"].(string)
	if !ok {
		t.Fatalf("uuid field missing or not a string: %#v", got["uuid"])
	}
	if uuid != "" {
		t.Fatalf("uuid = %q, want empty string on lookup failure", uuid)
	}
	if uuid == token {
		t.Fatalf("uuid must not leak the submitted token %q", token)
	}
}
