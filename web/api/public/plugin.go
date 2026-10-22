package public

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/internal/plugin"
)

// ServePluginFile serves a public iframe page declared in a plugin manifest
// (visibility=public). It is reachable without authentication; the plugin
// must be enabled and the requested file must be listed as a public page.
//
// 不用 c.File：http.ServeFile 会把 ".../index.html" 301 跳转到目录，而目录请求
// 在这里只会映射到已声明为公开的 index.html。直接打开文件交给 http.ServeContent，
// 既不列目录也不跳转。
func ServePluginFile(c *gin.Context) {
	name := strings.TrimPrefix(c.Param("filepath"), "/")
	full, err := plugin.ResolvePublicFile(c.Param("short"), name)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	file, err := os.Open(full)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		c.Status(http.StatusNotFound)
		return
	}
	http.ServeContent(c.Writer, c.Request, stat.Name(), stat.ModTime(), file)
}
