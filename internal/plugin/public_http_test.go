package plugin_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/internal/plugin"
	public_api "github.com/komari-monitor/komari/web/api/public"
)

// installPublicPlugin 安装并启用一个插件，返回挂了公开插件路由的 gin 引擎。
func installPublicPlugin(t *testing.T, short string, files map[string]string) *gin.Engine {
	t.Helper()
	plugin.WithTempDataDirForTest(t)
	if _, err := plugin.InstallZip(plugin.WritePluginZipForTest(t, files)); err != nil {
		t.Fatal(err)
	}
	if err := plugin.SetEnabled(short, true, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plugin.SetEnabled(short, false, false) })

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/plugin/:short/*filepath", public_api.ServePluginFile)
	return r
}

func getPluginPath(r *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func expectPluginPage(t *testing.T, r *gin.Engine, path, want string) {
	t.Helper()
	w := getPluginPath(r, path)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s = %d (Location %q), want 200", path, w.Code, w.Header().Get("Location"))
	}
	if !strings.Contains(w.Body.String(), want) {
		t.Fatalf("GET %s body = %q, want it to contain %q", path, w.Body.String(), want)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("GET %s Content-Type = %q", path, ct)
	}
}

func expectPluginNotFound(t *testing.T, r *gin.Engine, path string) {
	t.Helper()
	if w := getPluginPath(r, path); w.Code != http.StatusNotFound {
		t.Fatalf("GET %s = %d, want 404: %s", path, w.Code, w.Body.String())
	}
}

// 以前 c.File 底层的 http.ServeFile 会把 /index.html 301 到目录，而目录请求又被拒绝，
// 名为 index.html 的公开页面全部打不开。
func TestPublicPluginRootIndexOverHTTP(t *testing.T) {
	r := installPublicPlugin(t, "rootidx", map[string]string{
		"komari-plugin.json": `{"name":"RootIdx","short":"rootidx","version":"1.0.0","pages":[{"file":"index.html","title":"Root","visibility":"public"}]}`,
		"script.js":          `function load() {}`,
		"index.html":         `<h1>root page</h1>`,
		"secret.js":          `console.log("secret")`,
	})

	expectPluginPage(t, r, "/api/plugin/rootidx/index.html", "root page")
	expectPluginPage(t, r, "/api/plugin/rootidx/", "root page")
	expectPluginNotFound(t, r, "/api/plugin/rootidx/komari-plugin.json")
	expectPluginNotFound(t, r, "/api/plugin/rootidx/script.js")
	expectPluginNotFound(t, r, "/api/plugin/rootidx/secret.js")
}

func TestPublicPluginSubdirectoryIndexOverHTTP(t *testing.T) {
	r := installPublicPlugin(t, "subidx", map[string]string{
		"komari-plugin.json": `{"name":"SubIdx","short":"subidx","version":"1.0.0","pages":[{"file":"public/index.html","title":"Sub","visibility":"public"}]}`,
		"script.js":          `function load() {}`,
		"index.html":         `<h1>private root</h1>`,
		"public/index.html":  `<h1>sub page</h1>`,
		"public/app.js":      `console.log("app")`,
		"private/hidden.js":  `console.log("hidden")`,
	})

	expectPluginPage(t, r, "/api/plugin/subidx/public/index.html", "sub page")
	expectPluginPage(t, r, "/api/plugin/subidx/public/", "sub page")
	expectPluginPage(t, r, "/api/plugin/subidx/public", "sub page")
	if w := getPluginPath(r, "/api/plugin/subidx/public/app.js"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "app") {
		t.Fatalf("sibling asset: %d %q", w.Code, w.Body.String())
	}
	// 根目录的 index.html 没有声明为公开页面，目录请求不能借道拿到它。
	expectPluginNotFound(t, r, "/api/plugin/subidx/")
	expectPluginNotFound(t, r, "/api/plugin/subidx/index.html")
	expectPluginNotFound(t, r, "/api/plugin/subidx/komari-plugin.json")
	expectPluginNotFound(t, r, "/api/plugin/subidx/private/hidden.js")
	expectPluginNotFound(t, r, "/api/plugin/subidx/private/")
}

// 页面目录里没有 index.html 时，目录请求返回 404 而不是目录列表。
func TestPublicPluginDirectoryWithoutIndexIsNotListed(t *testing.T) {
	r := installPublicPlugin(t, "noidx", map[string]string{
		"komari-plugin.json": `{"name":"NoIdx","short":"noidx","version":"1.0.0","pages":[{"file":"pages/page.html","title":"Page","visibility":"public"}]}`,
		"script.js":          `function load() {}`,
		"pages/page.html":    `<h1>page</h1>`,
	})
	expectPluginPage(t, r, "/api/plugin/noidx/pages/page.html", "page")
	expectPluginNotFound(t, r, "/api/plugin/noidx/pages/")
	expectPluginNotFound(t, r, "/api/plugin/noidx/")
}
