package geoip // 与 geoip.go 保持相同的包名，表示它们是同一个包的组成部分

import (
	"fmt"
	logger "github.com/komari-monitor/komari/utils/log"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath" // 新增导入，用于处理文件路径
	"sync"
	"time"

	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/oschwald/maxminddb-golang"
)

// GeoIpUrl 是 MaxMind 数据库的下载地址。
var GeoIpUrl = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-Country.mmdb"

// GeoIpFilePath 是本地存储 MaxMind 数据库的路径。
var GeoIpFilePath = "./data/GeoLite2-Country.mmdb"

// GeoIpRecord 结构体定义了 MaxMind 数据库查询结果的原始结构。
// 它是 MaxMind 库特有的，用于从 .mmdb 文件中解析数据。
type GeoIpRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

// MaxMindGeoIPService 是 GeoIPService 接口的一个具体实现，
// 它使用 MaxMind 数据库作为后端。
type MaxMindGeoIPService struct {
	// maxMindDBReader 内部持有的 MaxMind 数据库读取器实例。
	maxMindDBReader *maxminddb.Reader
	// dbFilePath 是 MaxMind 数据库文件的路径。
	dbFilePath string
	// mu 用于保护对 maxMindDBReader 的并发访问，确保线程安全。
	mu sync.RWMutex
}

// Name 返回服务的名称。
func (s *MaxMindGeoIPService) Name() string {
	return "MaxMind"
}

// NewMaxMindGeoIPService 创建并返回一个 MaxMindGeoIPService 实例。
// 它负责初始化服务，包括尝试加载或下载数据库。
func NewMaxMindGeoIPService() (*MaxMindGeoIPService, error) {
	dbFilePath := GeoIpFilePath
	service := &MaxMindGeoIPService{
		dbFilePath: dbFilePath,
	}

	// 确保数据目录存在
	if err := os.MkdirAll(filepath.Dir(dbFilePath), os.ModePerm); err != nil {
		auditlog.Log("", "", "Failed to create data directory for MaxMind database: "+err.Error(), "error")
		return nil, fmt.Errorf("failed to create data directory for MaxMind database: %w", err)
	}

	// 检查数据库文件是否存在，如果不存在则尝试下载
	if _, err := os.Stat(dbFilePath); os.IsNotExist(err) {
		if err := service.UpdateDatabase(); err != nil {
			auditlog.Log("", "", "Failed to download initial MaxMind database: "+err.Error(), "error")
			return nil, fmt.Errorf("failed to download initial MaxMind database: %w", err)
		}
	}

	// 初始化或重新加载 MaxMind 数据库。
	if err := service.initialize(); err != nil {
		auditlog.Log("", "", "Failed to initialize MaxMind database: "+err.Error(), "error")
		return nil, fmt.Errorf("failed to initialize MaxMind database: %w", err)
	}
	return service, nil
}

// initialize 初始化或重新加载 MaxMind 数据库。
// 这是一个内部方法，供 NewMaxMindGeoIPService 调用。
// 它会关闭现有连接（如果存在）并重新打开数据库文件。
func (s *MaxMindGeoIPService) initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openLocked()
}

// openLocked 关闭现有 reader 并重新打开 s.dbFilePath。
// 调用方必须已持有 s.mu 的写锁；这样 UpdateDatabase 可以在
// 「关闭旧库 → 替换文件 → 打开新库」这一小段里复用同一套逻辑。
func (s *MaxMindGeoIPService) openLocked() error {
	// 如果已存在数据库读取器，则先关闭它。
	if s.maxMindDBReader != nil {
		s.maxMindDBReader.Close()
		s.maxMindDBReader = nil
	}

	// 尝试打开新的数据库文件。
	reader, err := maxminddb.Open(s.dbFilePath)
	if err != nil {
		return fmt.Errorf("error opening MaxMind database at %s: %w", s.dbFilePath, err)
	}
	s.maxMindDBReader = reader
	return nil
}

// GetGeoInfo 根据 IP 地址获取 MaxMind 的地理位置信息。
// 它查询 MaxMind 数据库并将其特有的 GeoIpRecord 转换为通用的 GeoInfo 结构体。
func (s *MaxMindGeoIPService) GetGeoInfo(ip net.IP) (*GeoInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.maxMindDBReader == nil {
		return nil, fmt.Errorf("MaxMind database is not initialized or failed to open")
	}
	if ip == nil {
		return nil, fmt.Errorf("IP address cannot be nil")
	}

	var record GeoIpRecord // 使用原始的 GeoIpRecord 结构体来接收查询结果
	err := s.maxMindDBReader.Lookup(ip, &record)
	if err != nil {
		// 返回错误，但避免直接返回 maxminddb 库的内部错误，提供更友好的信息
		return nil, fmt.Errorf("error looking up IP %s in MaxMind database: %w", ip.String(), err)
	}

	// 将 MaxMind 的特定结构体转换为通用的 GeoInfo 结构体
	geoInfo := &GeoInfo{
		ISOCode: record.Country.ISOCode,
		// 尝试获取英文国家名称，如果不存在则使用 ISO 代码作为备用
		Name: record.Country.Names["en"],
	}
	if geoInfo.Name == "" && geoInfo.ISOCode != "" {
		geoInfo.Name = geoInfo.ISOCode // 如果没有英文名称，回退到 ISO 代码
	}
	return geoInfo, nil
}

// maxDatabaseBytes 是单次允许下载的 MaxMind 数据库大小上限（200 MiB）。
const maxDatabaseBytes int64 = 200 << 20

// UpdateDatabase 实现了 GeoIPService 接口的 UpdateDatabase 方法。
// 它会下载最新的 GeoLite2-Country.mmdb 文件并重新加载数据库。
//
// 下载与校验都在锁外完成（网络耗时不能阻塞 GetGeoInfo），只有
// 「关闭旧 reader → rename 替换 → 打开新库」这一小段持有写锁。这样任何
// 失败路径都不会泄漏锁，也不会截断正在被读取的数据库文件。
func (s *MaxMindGeoIPService) UpdateDatabase() error {
	// 下载放在锁外，并带上超时，避免无响应的服务端把更新流程永久挂住。
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Get(GeoIpUrl) // GeoIpUrl 是预定义的 MaxMind 数据库下载地址
	if err != nil {
		return fmt.Errorf("failed to initiate MaxMind database download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download MaxMind database: HTTP status %s", resp.Status)
	}

	// 确保数据目录存在（NewMaxMindGeoIPService 已处理，但这里再次确保以防直接调用）
	dir := filepath.Dir(s.dbFilePath)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create data directory for MaxMind database update: %w", err)
	}

	// 先下载到同目录的临时文件，校验通过后再替换，避免下载失败/内容非法时
	// 留下被截断的数据库。同目录保证 rename 不会跨卷。
	tmp, err := os.CreateTemp(dir, ".mmdb-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary MaxMind database file: %w", err)
	}
	tmpName := tmp.Name()
	// rename 成功后该路径已不存在，Remove 失败可以忽略；失败路径则清掉临时文件。
	defer os.Remove(tmpName)

	// 多读 1 字节用于判断是否超过上限。
	written, err := io.Copy(tmp, io.LimitReader(resp.Body, maxDatabaseBytes+1))
	if err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write MaxMind database file: %w", err)
	}
	if written > maxDatabaseBytes {
		tmp.Close()
		return fmt.Errorf("downloaded MaxMind database exceeds the %d bytes limit", maxDatabaseBytes)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temporary MaxMind database file: %w", err)
	}

	// 探测下载内容是否为合法的 mmdb：非法则直接返回错误并保留旧库。
	probe, err := maxminddb.Open(tmpName)
	if err != nil {
		return fmt.Errorf("downloaded file is not a valid MaxMind database: %w", err)
	}
	probe.Close()

	// 只在这段持有写锁：Windows 上必须先关闭旧 reader 才能 rename 覆盖。
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.maxMindDBReader != nil {
		s.maxMindDBReader.Close()
		s.maxMindDBReader = nil
	}

	if err := os.Rename(tmpName, s.dbFilePath); err != nil {
		// 替换失败时把旧库重新打开，避免更新失败连带让查询不可用。
		if reopenErr := s.openLocked(); reopenErr != nil {
			return fmt.Errorf("failed to replace MaxMind database: %w (reopening the previous database also failed: %v)", err, reopenErr)
		}
		return fmt.Errorf("failed to replace MaxMind database: %w", err)
	}

	// 重新加载数据库以使用新下载的文件
	if err := s.openLocked(); err != nil {
		return fmt.Errorf("failed to reload MaxMind database after update: %w", err)
	}
	return nil
}

// Close 实现了 GeoIPService 接口的 Close 方法。
// 它关闭 MaxMind 数据库读取器，释放文件句柄和其他资源。
func (s *MaxMindGeoIPService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxMindDBReader != nil {
		err := s.maxMindDBReader.Close()
		s.maxMindDBReader = nil // 清空读取器实例
		if err != nil {
			return fmt.Errorf("error closing MaxMind database: %w", err)
		}
	}
	logger.InfoArgs("geoip", "MaxMind GeoIP service closed.")
	return nil
}
