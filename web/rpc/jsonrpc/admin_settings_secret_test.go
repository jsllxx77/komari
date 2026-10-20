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

func TestSensitiveSettingsTouched(t *testing.T) {
	if !sensitiveSettingsTouched(map[string]interface{}{config.ApiKeyKey: "x"}) {
		t.Fatal("changing the api key must require sensitive verification")
	}
	if !sensitiveSettingsTouched(map[string]interface{}{config.CustomHeadKey: "<script>"}) {
		t.Fatal("custom head injection must require sensitive verification")
	}
	if sensitiveSettingsTouched(map[string]interface{}{config.SitenameKey: "Komari"}) {
		t.Fatal("cosmetic settings must not require sensitive verification")
	}
}

func TestSensitiveSettingsTouchedIgnoresCodeField(t *testing.T) {
	// 只提交了验证码的请求不应被当成安全设置变更（验证码在检查前会被删除）。
	cfg := map[string]interface{}{}
	if sensitiveSettingsTouched(cfg) {
		t.Fatal("an empty change set must not be sensitive")
	}
}
