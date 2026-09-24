package flags

import "strings"

const (
	DatabaseTypeSQLite = "sqlite"
)

var (
	// 数据库配置
	DatabaseType string // 数据库类型：sqlite
	DatabaseFile string // SQLite数据库文件路径

	Listen string

	// TrustedProxies 允许提供 X-Forwarded-For / X-Real-IP 的代理地址（IP 或 CIDR，逗号分隔）。
	// 为空时使用本机与内网地址；"none" 表示不信任任何代理；"*" 表示信任所有来源。
	TrustedProxies string
)

func NormalizeDatabaseType(databaseType string) string {
	databaseType = strings.ToLower(strings.TrimSpace(databaseType))
	if databaseType == "" {
		return DatabaseTypeSQLite
	}
	return databaseType
}

func ApplyDatabaseTypeNormalization() string {
	DatabaseType = NormalizeDatabaseType(DatabaseType)
	return DatabaseType
}

func IsSQLite() bool {
	return NormalizeDatabaseType(DatabaseType) == DatabaseTypeSQLite
}

func SupportedDatabaseTypes() string {
	return DatabaseTypeSQLite
}
