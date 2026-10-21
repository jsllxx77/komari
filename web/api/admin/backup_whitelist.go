package admin

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/komari-monitor/komari/internal/plugin"
)

// backupDataRoot 是备份的根目录：白名单项都是相对它的路径。
var backupDataRoot = filepath.Join(".", "data")

// backupWhitelist 定义需要备份的 ./data/ 下文件/目录（相对路径）。
// 目录项会递归包含其下所有文件。新增需持久化数据时在此追加。
//
// 目录项一律用 dirEntryFor 从代码里真实使用的目录常量/路径推导，避免再次
// 手写目录名拼错：历史 bug 写成了 "plguin-data/"，与真实目录
// ./data/plugin-data 不一致，导致插件持久化数据进不了备份，而恢复流程会先
// 清空 ./data 再解压，于是这些数据被静默删除。
//
// 注意：komari.db 不在白名单中——database 通过 DownloadBackup 中的
// SQLite VACUUM INTO 或 copyFile 单独备份，确保一致性快照。
// GeoLite2-Country.mmdb 同样不需要备份：启动时会自动重新下载。
var backupWhitelist = []string{
	"favicon.ico",
	"font.ttf",
	dirEntryFor("./data/theme"),    // 见 web/api/admin/theme.go 与 internal/server/bootstrap.go
	dirEntryFor(plugin.DataDir),    // 插件安装目录，见 internal/plugin/plugin.go
	dirEntryFor(plugin.StorageDir), // 插件持久化数据，见 internal/plugin/plugin.go 的 StorageDir
	"metrics.db",
}

// dirEntryFor 把 ./data 下的目录路径转换为白名单项：相对 backupDataRoot 的
// 正斜杠路径并补上结尾 "/"。传入路径无法相对化时按原样返回，避免产生空项。
func dirEntryFor(dir string) string {
	clean := filepath.Clean(dir)
	rel, err := filepath.Rel(backupDataRoot, clean)
	if err != nil {
		return filepath.ToSlash(clean) + "/"
	}
	return filepath.ToSlash(rel) + "/"
}

// copyWhitelistedFiles 将白名单中存在的文件/目录复制到临时目录。
// 不存在的项静默跳过，确保白名单扩展的向前兼容。
func copyWhitelistedFiles(tempDir string) error {
	return copyWhitelistedFilesFrom(backupDataRoot, tempDir)
}

func copyWhitelistedFilesFrom(dataDir, tempDir string) error {
	for _, relPath := range backupWhitelist {
		src := filepath.Join(dataDir, relPath)
		info, err := os.Stat(src)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("stat whitelist entry %s: %v", relPath, err)
		}
		if info.IsDir() {
			if err := copyDir(src, filepath.Join(tempDir, relPath)); err != nil {
				return fmt.Errorf("copy whitelist dir %s: %v", relPath, err)
			}
		} else {
			if err := copyFile(src, filepath.Join(tempDir, relPath)); err != nil {
				return fmt.Errorf("copy whitelist file %s: %v", relPath, err)
			}
		}
	}
	return nil
}

// copyDir 递归复制目录到目标路径。
func copyDir(srcDir, dstDir string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dst := filepath.Join(dstDir, rel)
		if info.IsDir() {
			return os.MkdirAll(dst, 0755)
		}
		return copyFile(path, dst)
	})
}
