package admin

import (
	"strings"
	"testing"

	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/internal/config"
)

// setupMarketSSRFConfigDB makes sure the config store backing
// ssrfProtectionEnabled() exists and that the SSRF setting is absent, which is
// what a fresh install or an upgraded legacy install looks like.
func setupMarketSSRFConfigDB(t *testing.T) {
	t.Helper()

	flags.DatabaseType = "sqlite"
	flags.DatabaseFile = "file:web_admin_market_download_ssrf?mode=memory&cache=shared"
	db := dbcore.GetDBInstance()

	clearMarketSSRFConfig := func() {
		if err := db.Exec("DELETE FROM configs WHERE key = ?", config.SSRFProtectionEnabledKey).Error; err != nil {
			t.Fatalf("reset %s: %v", config.SSRFProtectionEnabledKey, err)
		}
	}
	clearMarketSSRFConfig()
	t.Cleanup(func() {
		_ = db.Exec("DELETE FROM configs WHERE key = ?", config.SSRFProtectionEnabledKey).Error
	})
}

func TestSSRFProtectionEnabledDefaultsToTrue(t *testing.T) {
	setupMarketSSRFConfigDB(t)

	enabled, err := ssrfProtectionEnabled()
	if err != nil {
		t.Fatalf("ssrfProtectionEnabled() error = %v, want nil when the setting is absent", err)
	}
	if !enabled {
		t.Fatal("ssrfProtectionEnabled() = false, want true when the setting is absent")
	}
	if !IsSSRFProtectionEnabled() {
		t.Fatal("IsSSRFProtectionEnabled() = false, want true when the setting is absent")
	}

	stored, err := config.GetAs[bool](config.SSRFProtectionEnabledKey)
	if err != nil {
		t.Fatalf("config.GetAs(%s) error = %v", config.SSRFProtectionEnabledKey, err)
	}
	if !stored {
		t.Fatal("the default was not persisted as true, so upgraded installations would stay unprotected")
	}
}

func TestSSRFProtectionExplicitValueIsHonoured(t *testing.T) {
	setupMarketSSRFConfigDB(t)

	if err := config.Set(config.SSRFProtectionEnabledKey, false); err != nil {
		t.Fatalf("set %s: %v", config.SSRFProtectionEnabledKey, err)
	}
	enabled, err := ssrfProtectionEnabled()
	if err != nil {
		t.Fatalf("ssrfProtectionEnabled() error = %v", err)
	}
	if enabled {
		t.Fatal("ssrfProtectionEnabled() = true, want the explicitly configured false")
	}
}

// dangerousTarget pairs a rejected URL with the subtext its rejection error
// must carry, so the test proves the URL was refused by validation rather than
// by an incidental connection error.
type dangerousTarget struct {
	target      string
	wantErrText string
}

func dangerousMarketDownloadTargets() []dangerousTarget {
	return []dangerousTarget{
		{target: "http://127.0.0.1/x", wantErrText: "loopback"},
		{target: "http://127.1.2.3/x", wantErrText: "loopback"}, // Anywhere in 127.0.0.0/8.
		{target: "http://169.254.169.254/latest/meta-data/", wantErrText: "loopback"},
		{target: "http://[::1]/x", wantErrText: "loopback"},
		{target: "http://[fe80::1]/x", wantErrText: "loopback"},
		{target: "http://0.0.0.0/x", wantErrText: "loopback"},
		{target: "http://[::]/x", wantErrText: "loopback"},
		{target: "file:///etc/passwd", wantErrText: "only HTTP and HTTPS"},
		{target: "http://user:pass@example.com/", wantErrText: "only HTTP and HTTPS"},
	}
}

func TestValidateMarketDownloadTargetRejectsObviousDangerousTargets(t *testing.T) {
	for _, tt := range dangerousMarketDownloadTargets() {
		t.Run(tt.target, func(t *testing.T) {
			err := validateMarketDownloadTarget(tt.target)
			if err == nil {
				t.Fatalf("validateMarketDownloadTarget(%q) = nil, want error", tt.target)
			}
			if !strings.Contains(err.Error(), tt.wantErrText) {
				t.Fatalf("validateMarketDownloadTarget(%q) error = %q, want it to mention %q", tt.target, err, tt.wantErrText)
			}
		})
	}
}

// Self-hosted intranet markets are a supported deployment, so private ranges
// must keep working when SSRF protection is switched off.
func TestValidateMarketDownloadTargetAllowsPrivateMarkets(t *testing.T) {
	for _, target := range []string{
		"http://10.1.2.3/market.json",
		"http://172.16.0.5/market.json",
		"http://192.168.1.10/market.json",
	} {
		t.Run(target, func(t *testing.T) {
			if err := validateMarketDownloadTarget(target); err != nil {
				t.Fatalf("validateMarketDownloadTarget(%q) error = %v, want nil", target, err)
			}
		})
	}
}

func TestDownloadMarketURLRejectsDangerousTargetsEvenWhenProtectionDisabled(t *testing.T) {
	setupMarketSSRFConfigDB(t)
	if err := config.Set(config.SSRFProtectionEnabledKey, false); err != nil {
		t.Fatalf("set %s: %v", config.SSRFProtectionEnabledKey, err)
	}

	for _, tt := range dangerousMarketDownloadTargets() {
		t.Run(tt.target, func(t *testing.T) {
			// All of these are rejected before any connection is attempted, so the
			// test never touches the network.
			_, err := DownloadMarketURL(tt.target, 4096)
			if err == nil {
				t.Fatalf("DownloadMarketURL(%q) = nil error with protection disabled, want rejection", tt.target)
			}
			if !strings.Contains(err.Error(), tt.wantErrText) {
				t.Fatalf("DownloadMarketURL(%q) error = %q, want it to mention %q", tt.target, err, tt.wantErrText)
			}
		})
	}
}

func TestDownloadMarketURLRejectsDangerousTargetsWithProtectionEnabled(t *testing.T) {
	setupMarketSSRFConfigDB(t)

	for _, tt := range dangerousMarketDownloadTargets() {
		t.Run(tt.target, func(t *testing.T) {
			_, err := DownloadMarketURL(tt.target, 4096)
			if err == nil {
				t.Fatalf("DownloadMarketURL(%q) = nil error with protection enabled, want rejection", tt.target)
			}
			if !strings.Contains(err.Error(), tt.wantErrText) {
				t.Fatalf("DownloadMarketURL(%q) error = %q, want it to mention %q", tt.target, err, tt.wantErrText)
			}
		})
	}
}
