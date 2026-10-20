package client

import (
	"testing"
	"time"

	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	v2 "github.com/komari-monitor/komari/protocol/v2"
)

func TestSanitizeAgentBasicInfoDropsAdministrativeFields(t *testing.T) {
	in := map[string]interface{}{
		"os":            "Linux",
		"mem_total":     1024,
		"region":        "🏴",          // 服务端计算，不接受上报
		"expired_at":    "2099-01-01", //
		"traffic_limit": 0,            //
		"token":         "attacker-token",
		"hidden":        true,
		"name":          "pwned",
		"price":         0,
		"group":         "vip",
		"uuid":          "other-client",
		"cpu_name":      "short",
	}

	out := sanitizeAgentBasicInfo(in)

	if out["os"] != "Linux" || out["cpu_name"] != "short" {
		t.Fatalf("hardware fields were dropped: %#v", out)
	}
	if _, ok := out["mem_total"]; !ok {
		t.Fatalf("numeric hardware field was dropped: %#v", out)
	}
	for _, key := range []string{"region", "expired_at", "traffic_limit", "token", "hidden", "name", "price", "group", "uuid"} {
		if _, ok := out[key]; ok {
			t.Fatalf("field %q must not be accepted from an agent, got %#v", key, out)
		}
	}
}

func TestSanitizeAgentBasicInfoTruncatesLongStrings(t *testing.T) {
	long := ""
	for i := 0; i < 300; i++ {
		long += "机"
	}
	out := sanitizeAgentBasicInfo(map[string]interface{}{
		"os":       long,
		"gpu_name": "abcd",
	})
	osValue, _ := out["os"].(string)
	if len(osValue) > agentBasicInfoStringFields["os"] {
		t.Fatalf("os was not truncated: %d bytes", len(osValue))
	}
	if len(osValue)%3 != 0 || osValue == "" {
		// 必须是合法的 UTF-8 前缀：不能切在多字节字符中间
		t.Fatalf("os was cut inside a rune: %q", osValue)
	}
	if out["gpu_name"] != "abcd" {
		t.Fatalf("short value changed: %#v", out["gpu_name"])
	}
}

func TestV2BasicInfoCannotOverwriteAdministrativeFields(t *testing.T) {
	flags.DatabaseType = "sqlite"
	flags.DatabaseFile = "file:v2_basic_info_whitelist?mode=memory&cache=shared"

	db := dbcore.GetDBInstance()
	clientUUID := "client-v2-whitelist"
	token := "token-v2-whitelist"
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()
	if err := db.Create(&models.Client{
		UUID:         clientUUID,
		Token:        token,
		Name:         "keep-me",
		Group:        "",
		Hidden:       true,
		Price:        1.5,
		TrafficLimit: 1000,
		ExpiredAt:    &expiry,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Where("uuid = ?", clientUUID).Delete(&models.Client{}).Error
	})

	resp := handleV2RPC(clientUUID, v2.Request{
		JSONRPC: v2.Version,
		Method:  v2.MethodAgentBasicInfo,
		Params: map[string]interface{}{
			"info": map[string]interface{}{
				"os":            "Linux",
				"mem_total":     float64(2048),
				"expired_at":    "2099-01-01T00:00:00Z",
				"traffic_limit": float64(0),
				"token":         "attacker-token",
				"hidden":        false,
				"name":          "pwned",
				"price":         float64(0),
				"group":         "vip",
				"weight":        float64(999),
			},
		},
		ID: "basic-info-whitelist",
	}, false)
	if resp.Error != nil {
		t.Fatalf("v2 basic info failed: %+v", resp.Error)
	}

	var got models.Client
	if err := db.First(&got, "uuid = ?", clientUUID).Error; err != nil {
		t.Fatalf("load client: %v", err)
	}
	if got.OS != "Linux" || got.MemTotal != 2048 {
		t.Fatalf("hardware fields were not saved: os=%q mem=%d", got.OS, got.MemTotal)
	}
	if got.Name != "keep-me" || got.Token != token || got.Hidden != true ||
		got.Price != 1.5 || got.TrafficLimit != 1000 || got.Group != "" || got.Weight != 0 {
		t.Fatalf("administrative fields changed: %#v", got)
	}
	if got.ExpiredAt == nil || !got.ExpiredAt.UTC().Equal(expiry) {
		t.Fatalf("expired_at changed: %v", got.ExpiredAt)
	}
}
