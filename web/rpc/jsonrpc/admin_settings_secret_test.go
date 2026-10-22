package jsonrpc

import (
	"testing"

	"github.com/komari-monitor/komari/internal/config"
)

func TestMaskSecretSettings(t *testing.T) {
	masked := maskSecretSettings(map[string]interface{}{
		config.ApiKeyKey:           "supersecretapikey1234",
		config.AutoDiscoveryKeyKey: "discovery-key-abcd",
		config.SitenameKey:         "Komari",
		"empty_secret":             "",
	})

	if got := masked[config.ApiKeyKey]; got != "****1234" {
		t.Fatalf("api key was not masked: %v", got)
	}
	if got := masked[config.AutoDiscoveryKeyKey]; got != "****abcd" {
		t.Fatalf("auto discovery key was not masked: %v", got)
	}
	if got := masked[config.SitenameKey]; got != "Komari" {
		t.Fatalf("non-secret setting must stay readable: %v", got)
	}
}

func TestMaskSecretValueKeepsShortSecretsOpaque(t *testing.T) {
	if got := maskSecretValue("abc"); got != maskedSecretPlaceholder {
		t.Fatalf("short secret leaked: %q", got)
	}
	if got := maskSecretValue(""); got != "" {
		t.Fatalf("empty secret must stay empty, got %q", got)
	}
}

func TestStripMaskedSecretsKeepsStoredValue(t *testing.T) {
	cfg := map[string]interface{}{
		config.ApiKeyKey:           "****1234",
		config.AutoDiscoveryKeyKey: "brand-new-key",
		config.SitenameKey:         "Komari",
	}
	stripMaskedSecrets(cfg)

	if _, ok := cfg[config.ApiKeyKey]; ok {
		t.Fatal("a masked api key must not be written back")
	}
	if cfg[config.AutoDiscoveryKeyKey] != "brand-new-key" {
		t.Fatal("a freshly supplied key must be kept")
	}
	if cfg[config.SitenameKey] != "Komari" {
		t.Fatal("unrelated settings must be kept")
	}
}

func TestSensitiveSettingsChanged(t *testing.T) {
	current := map[string]interface{}{
		config.ApiKeyKey:                 "stored-api-key-1234",
		config.CustomHeadKey:             "",
		config.CorsAllowedOriginsKey:     "https://a.example",
		config.CorsOriginCheckEnabledKey: true,
	}
	if !sensitiveSettingsChanged(map[string]interface{}{config.ApiKeyKey: "x"}, current) {
		t.Fatal("changing the api key must require sensitive verification")
	}
	if !sensitiveSettingsChanged(map[string]interface{}{config.ApiKeyKey: ""}, current) {
		t.Fatal("clearing the api key must require sensitive verification")
	}
	if !sensitiveSettingsChanged(map[string]interface{}{config.CustomHeadKey: "<script>"}, current) {
		t.Fatal("custom head injection must require sensitive verification")
	}
	if sensitiveSettingsChanged(map[string]interface{}{config.SitenameKey: "Komari"}, current) {
		t.Fatal("cosmetic settings must not require sensitive verification")
	}
	// 整表保存：安全相关键原样提交（值没变），不算修改。
	unchanged := map[string]interface{}{
		config.SitenameKey:               "New name",
		config.CustomHeadKey:             "",
		config.CorsAllowedOriginsKey:     "https://a.example",
		config.CorsOriginCheckEnabledKey: true,
	}
	if sensitiveSettingsChanged(unchanged, current) {
		t.Fatal("re-submitting the stored values must not count as a sensitive change")
	}
	// 库里没有的键按默认值比较：ssrf_protection_enabled 默认 true。
	if sensitiveSettingsChanged(map[string]interface{}{config.SSRFProtectionEnabledKey: true}, current) {
		t.Fatal("submitting the default value of a missing key is not a change")
	}
	if !sensitiveSettingsChanged(map[string]interface{}{config.SSRFProtectionEnabledKey: false}, current) {
		t.Fatal("turning SSRF protection off must require sensitive verification")
	}
	// 只提交了验证码的请求不应被当成安全设置变更（验证码在检查前会被删除）。
	if sensitiveSettingsChanged(map[string]interface{}{}, current) {
		t.Fatal("an empty change set must not be sensitive")
	}
}

func TestStripMaskedSecretsKeepsEmptyValue(t *testing.T) {
	cfg := map[string]interface{}{config.ApiKeyKey: ""}
	stripMaskedSecrets(cfg)
	if value, ok := cfg[config.ApiKeyKey]; !ok || value != "" {
		t.Fatal("an empty api key clears the key and must be kept")
	}
}
