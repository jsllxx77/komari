package admin

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/komari-monitor/komari/internal/plugin"
)

// TestBackupWhitelistUsesRealPluginDataDir 断言插件持久化数据目录的拼写与
// internal/plugin.StorageDir 一致（历史 bug：白名单写成 "plguin-data/"）。
func TestBackupWhitelistUsesRealPluginDataDir(t *testing.T) {
	if !slices.Contains(backupWhitelist, "plugin-data/") {
		t.Fatalf("backupWhitelist is missing plugin-data/, got %v", backupWhitelist)
	}
	if slices.Contains(backupWhitelist, "plguin-data/") {
		t.Fatalf("backupWhitelist contains the misspelled plguin-data/, got %v", backupWhitelist)
	}

	wantEntry := dirEntryFor(plugin.StorageDir)
	if wantEntry != "plugin-data/" {
		t.Fatalf("plugin.StorageDir (%q) no longer maps to plugin-data/, got %q", plugin.StorageDir, wantEntry)
	}
	if !slices.Contains(backupWhitelist, wantEntry) {
		t.Fatalf("backupWhitelist entry %q derived from plugin.StorageDir is missing, got %v", wantEntry, backupWhitelist)
	}
	// 白名单项必须实际指向 plugin.StorageDir，而不是别处的同名目录。
	if got := filepath.Join(backupDataRoot, wantEntry); filepath.Clean(got) != filepath.Clean(plugin.StorageDir) {
		t.Fatalf("whitelist entry %q resolves to %q, want %q", wantEntry, got, plugin.StorageDir)
	}
}

// TestBackupWhitelistDirEntriesMatchCode 断言每个目录类白名单项都能对应到
// 代码里真实使用的目录，且解析出的路径与之一致。
func TestBackupWhitelistDirEntriesMatchCode(t *testing.T) {
	realDirs := []string{
		"./data/theme",
		plugin.DataDir,
		plugin.StorageDir,
	}
	derived := make(map[string]string, len(realDirs))
	for _, dir := range realDirs {
		derived[dirEntryFor(dir)] = dir
	}

	for _, entry := range backupWhitelist {
		if !strings.HasSuffix(entry, "/") {
			continue // 文件项，如 favicon.ico / metrics.db
		}
		dir, ok := derived[entry]
		if !ok {
			t.Errorf("directory whitelist entry %q does not correspond to any directory used in code", entry)
			continue
		}
		if got := filepath.Join(backupDataRoot, entry); filepath.Clean(got) != filepath.Clean(dir) {
			t.Errorf("whitelist entry %q resolves to %q, want %q", entry, got, dir)
		}
	}
}

// TestBackupWhitelistExcludesRedownloadableFiles 断言会在启动时自动重新下载的
// GeoIP 数据库不在白名单里。
func TestBackupWhitelistExcludesRedownloadableFiles(t *testing.T) {
	for _, entry := range backupWhitelist {
		if strings.Contains(strings.ToLower(entry), ".mmdb") {
			t.Errorf("backupWhitelist should not contain the auto-downloaded GeoIP database: %q", entry)
		}
	}
}
