package geoip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestService 构造一个不依赖 NewMaxMindGeoIPService 的服务实例，
// 数据库路径指向临时目录，避免污染真实 ./data。
func newTestService(t *testing.T) (*MaxMindGeoIPService, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "GeoLite2-Country.mmdb")
	return &MaxMindGeoIPService{dbFilePath: dbPath}, dbPath
}

// TestUpdateDatabaseFailureKeepsServiceUsable 验证更新失败后锁不会泄漏：
// GetGeoInfo 必须能立即返回（返回错误也可以），而不是永久阻塞。
func TestUpdateDatabaseFailureKeepsServiceUsable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	originalURL := GeoIpUrl
	GeoIpUrl = srv.URL
	t.Cleanup(func() { GeoIpUrl = originalURL })

	service, _ := newTestService(t)

	if err := service.UpdateDatabase(); err == nil {
		t.Fatal("expected UpdateDatabase to fail on HTTP 500, got nil")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 错误可以接受：此时本地没有有效数据库，关键在于不能卡住。
		_, _ = service.GetGeoInfo(net.ParseIP("8.8.8.8"))
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("GetGeoInfo blocked for more than 2s after a failed UpdateDatabase: mutex was leaked")
	}
}

// TestUpdateDatabaseRejectsInvalidMMDB 验证下载到非 mmdb 内容时报错，
// 且原数据库文件不被替换、临时文件被清理。
func TestUpdateDatabaseRejectsInvalidMMDB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("this is definitely not a maxmind database"))
	}))
	defer srv.Close()

	originalURL := GeoIpUrl
	GeoIpUrl = srv.URL
	t.Cleanup(func() { GeoIpUrl = originalURL })

	service, dbPath := newTestService(t)
	originalContent := []byte("original-database-content")
	if err := os.WriteFile(dbPath, originalContent, 0o644); err != nil {
		t.Fatalf("failed to seed original database: %v", err)
	}

	if err := service.UpdateDatabase(); err == nil {
		t.Fatal("expected UpdateDatabase to reject an invalid mmdb, got nil")
	}

	got, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("failed to read database file after rejected update: %v", err)
	}
	if string(got) != string(originalContent) {
		t.Errorf("original database was replaced by invalid content: got %q", string(got))
	}

	entries, err := os.ReadDir(filepath.Dir(dbPath))
	if err != nil {
		t.Fatalf("failed to list database directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mmdb-") && strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("temporary download file was not cleaned up: %s", entry.Name())
		}
	}
}
