package plugin

import "testing"

// 供外部测试包（plugin_test）使用的测试辅助函数。

// WithTempDataDirForTest 见 withTempDataDir。
func WithTempDataDirForTest(t *testing.T) { withTempDataDir(t) }

// WritePluginZipForTest 见 writePluginZip。
func WritePluginZipForTest(t *testing.T, files map[string]string) string {
	return writePluginZip(t, files)
}
