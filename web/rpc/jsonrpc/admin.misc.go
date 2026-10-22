package jsonrpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/database/records"
	"github.com/komari-monitor/komari/database/tasks"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/internal/lifecycle"
	"github.com/komari-monitor/komari/internal/metricstore"
	"github.com/komari-monitor/komari/pkg/rpc"
	"github.com/komari-monitor/komari/web/api"
)

// admin.misc.go
// 杂项 admin RPC2 方法：会话管理、设置、客户端排序。

func parseUintKey(s string) (uint, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	return uint(v), err
}

func init() {
	RegisterWithGroupAndMeta("getSessions", rpc.RoleAdmin, adminGetSessions, &rpc.MethodMeta{
		Name:    "admin:getSessions",
		Summary: "List all login sessions (plaintext session is never returned)",
		Returns: "{ data: Session[] } where Session = { id, ...fields, current }",
	})
	RegisterWithGroupAndMeta("deleteSession", rpc.RoleAdmin, adminDeleteSession, &rpc.MethodMeta{
		Name:    "admin:deleteSession",
		Summary: "Delete a session by opaque id (or, transitionally, by plaintext token)",
		Params: []rpc.ParamMeta{
			{Name: "id", Type: "string", Required: false, Description: "Opaque session id from admin:getSessions"},
			{Name: "session", Type: "string", Required: false, Description: "Deprecated plaintext session token"},
		},
		Returns: "null",
	})
	RegisterWithGroupAndMeta("deleteAllSessions", rpc.RoleAdmin, adminDeleteAllSessions, &rpc.MethodMeta{
		Name:    "admin:deleteAllSessions",
		Summary: "Delete all sessions",
		Returns: "null",
	})
	RegisterWithGroupAndMeta("getSettings", rpc.RoleAdmin, adminGetSettings, &rpc.MethodMeta{
		Name:    "admin:getSettings",
		Summary: "Get all settings",
		Returns: "object",
	})
	RegisterWithGroupAndMeta("editSettings", rpc.RoleAdmin, adminEditSettings, &rpc.MethodMeta{
		Name:    "admin:editSettings",
		Summary: "Update settings (partial)",
		Returns: "null | { restart_required: true, guide_path: string }",
	})
	RegisterWithGroupAndMeta("revealSecret", rpc.RoleAdmin, adminRevealSecret, &rpc.MethodMeta{
		Name:    "admin:revealSecret",
		Summary: "Reveal a masked secret setting (sensitive, requires 2FA)",
		Params: []rpc.ParamMeta{
			{Name: "key", Type: "string", Required: true, Description: "api_key | auto_discovery_key"},
		},
		Returns: "{ key: string, value: string }",
	})
	RegisterWithGroupAndMeta("clearAllRecords", rpc.RoleAdmin, adminClearAllRecords, &rpc.MethodMeta{
		Name:    "admin:clearAllRecords",
		Summary: "Delete all load and ping records",
		Returns: "null",
	})
	RegisterWithGroupAndMeta("orderClients", rpc.RoleAdmin, adminOrderClients, &rpc.MethodMeta{
		Name:    "admin:orderClients",
		Summary: "Reorder clients (map of uuid->weight)",
		Returns: "null",
	})
}

// sessionResponse 是 admin:getSessions 返回给前端的会话视图。
// 它故意不含明文 session：前端只拿到稳定、不可逆的 id 与 current 标记，
// 即使响应被读取也无法据此伪造或复用一个可用的会话 token。
type sessionResponse struct {
	ID              string     `json:"id"`
	UUID            string     `json:"uuid"`
	UserAgent       string     `json:"user_agent"`
	IP              string     `json:"ip"`
	LoginMethod     string     `json:"login_method"`
	LatestOnline    time.Time  `json:"latest_online"`
	LatestUserAgent string     `json:"latest_user_agent"`
	LatestIP        string     `json:"latest_ip"`
	Expires         time.Time  `json:"expires"`
	MfaVerifiedAt   *time.Time `json:"mfa_verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
	Current         bool       `json:"current"`
}

// sessionID 计算会话的对外标识：hex(sha256(session)) 取前 16 个十六进制字符
// （64 位）。只是哈希前缀，无法从 id 反推出明文 token；同一 session 结果稳定。
func sessionID(session string) string {
	sum := sha256.Sum256([]byte(session))
	return hex.EncodeToString(sum[:])[:16]
}

func adminGetSessions(ctx context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	ss, err := accounts.GetAllSessions()
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to retrieve sessions: "+err.Error(), nil)
	}
	current := ""
	if meta := rpc.MetaFromContext(ctx); meta != nil {
		current = meta.SessionToken
	}
	data := make([]sessionResponse, 0, len(ss))
	for _, s := range ss {
		data = append(data, sessionResponse{
			ID:              sessionID(s.Session),
			UUID:            s.UUID,
			UserAgent:       s.UserAgent,
			IP:              s.Ip,
			LoginMethod:     s.LoginMethod,
			LatestOnline:    s.LatestOnline,
			LatestUserAgent: s.LatestUserAgent,
			LatestIP:        s.LatestIp,
			Expires:         s.Expires,
			MfaVerifiedAt:   s.MfaVerifiedAt,
			CreatedAt:       s.CreatedAt,
			Current:         current != "" && s.Session == current,
		})
	}
	return map[string]any{"data": data}, nil
}

// adminDeleteSession 删除一个会话。优先按 admin:getSessions 返回的不透明 id
// （服务端遍历现存会话比对）删除；过渡期仍接受明文 session，保持旧行为。
func adminDeleteSession(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params struct {
		Session string `json:"session"`
		ID      string `json:"id"`
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid request body: "+err.Error(), nil)
	}
	target := strings.TrimSpace(params.Session)
	id := strings.TrimSpace(params.ID)
	if target == "" && id == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "session or id is required", nil)
	}

	if id != "" {
		// 只信任服务端现存的 session 列表：用 id 反查真实 token 后再删除。
		ss, err := accounts.GetAllSessions()
		if err != nil {
			return nil, rpc.MakeError(rpc.InternalError, "Failed to retrieve sessions: "+err.Error(), nil)
		}
		matched := ""
		for _, s := range ss {
			if strings.EqualFold(sessionID(s.Session), id) {
				matched = s.Session
				break
			}
		}
		if matched == "" {
			return nil, rpc.MakeError(rpc.InvalidParams, "session not found", nil)
		}
		target = matched
	}

	if err := accounts.DeleteSession(target); err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to delete session: "+err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, "delete session", "info")
	return nil, nil
}

func adminDeleteAllSessions(ctx context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	if err := accounts.DeleteAllSessions(); err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to delete all sessions: "+err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, "delete all sessions", "warn")
	return nil, nil
}

func adminGetSettings(_ context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	cst, err := config.GetAll()
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to get settings: "+err.Error(), nil)
	}
	// 密钥类配置只返回打码值：拿到会话 cookie 的攻击者不应能直接读出 api_key。
	// 需要明文时走 admin:revealSecret（敏感操作）。
	return maskSecretSettings(cst), nil
}

// sensitiveSettingKeys 是与认证、授权、注入相关的配置键：修改它们需要敏感操作
// 二次验证（step-up）。普通展示类设置（站点名、描述等）不受影响，避免每次保存
// 设置都要求输入验证码。
var sensitiveSettingKeys = map[string]struct{}{
	config.ApiKeyKey:                 {},
	config.AutoDiscoveryKeyKey:       {},
	config.DisablePasswordLoginKey:   {},
	config.OAuthEnabledKey:           {},
	config.OAuthProviderKey:          {},
	config.CorsOriginCheckEnabledKey: {},
	config.CorsAllowedOriginsKey:     {},
	config.WsOriginCheckEnabledKey:   {},
	config.WsAllowedOriginsKey:       {},
	config.PrivateSiteKey:            {},
	config.SSRFProtectionEnabledKey:  {},
	config.CustomHeadKey:             {},
	config.CustomBodyKey:             {},
	config.ScriptDomainKey:           {},
	config.BaseScriptsURLKey:         {},
}

// secretSettingKeys 是需要在读取时打码的配置键。
var secretSettingKeys = map[string]struct{}{
	config.ApiKeyKey:           {},
	config.AutoDiscoveryKeyKey: {},
}

const maskedSecretPlaceholder = "****"

// maskSecretValue 保留后 4 位，其余用星号代替；空值保持为空。
func maskSecretValue(value string) string {
	if value == "" {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= 4 {
		return maskedSecretPlaceholder
	}
	return maskedSecretPlaceholder + string(runes[len(runes)-4:])
}

func maskSecretSettings(settings map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(settings))
	for key, value := range settings {
		out[key] = value
	}
	for key := range secretSettingKeys {
		if raw, ok := out[key].(string); ok {
			out[key] = maskSecretValue(raw)
		}
	}
	return out
}

// stripMaskedSecrets 丢弃仍然是打码值的密钥字段：前端把打码值原样提交回来时，
// 不应把真正的密钥覆盖成 "****1234"。空字符串是"清空密钥"，必须照常写入
// （设置页清空 API key 时提交的就是 api_key: ""）。
func stripMaskedSecrets(cfg map[string]interface{}) {
	for key := range secretSettingKeys {
		value, ok := cfg[key].(string)
		if !ok {
			continue
		}
		if value != "" && strings.HasPrefix(value, maskedSecretPlaceholder) {
			delete(cfg, key)
		}
	}
}

// twoFactorParamKeys 是参数里可以携带验证码的字段名。它们只用于校验，
// 保存设置前必须全部删除，不能被当成配置项写进库。
var twoFactorParamKeys = []string{"2fa_code", "two_factor_code", "otp"}

// takeSettingsTwoFactorCode 取出并删除参数里的验证码；参数里没有时使用
// 请求头（X-2FA-Code / X-Two-Factor-Code，由传输层放进 meta）里的验证码。
func takeSettingsTwoFactorCode(ctx context.Context, cfg map[string]interface{}) string {
	code := ""
	for _, key := range twoFactorParamKeys {
		if value, ok := cfg[key].(string); ok && value != "" && code == "" {
			code = value
		}
		delete(cfg, key)
	}
	if code == "" {
		if meta := rpc.MetaFromContext(ctx); meta != nil {
			code = meta.TwoFACode
		}
	}
	return code
}

// settingDefaults 是 config.Settings 上 default 标签给出的默认值（已按 JSON
// 解码后的形态表示），用于在库里还没有某个键时判断提交值是否真的改变了配置。
var settingDefaults = sync.OnceValue(func() map[string]any {
	out := make(map[string]any)
	t := reflect.TypeOf(config.Settings{})
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		def, ok := field.Tag.Lookup("default")
		if name == "" || name == "-" || !ok {
			continue
		}
		switch field.Type.Kind() {
		case reflect.Bool:
			if v, err := strconv.ParseBool(def); err == nil {
				out[name] = v
			}
		case reflect.String:
			out[name] = def
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
			if v, err := strconv.ParseFloat(def, 64); err == nil {
				out[name] = v
			}
		}
	}
	return out
})

// normalizeSettingValue 把值按 JSON 往返一次，使提交值与库里解码出的值可以直接比较。
func normalizeSettingValue(value any) any {
	raw, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return value
	}
	return out
}

// sensitiveSettingsChanged 判断本次提交是否真的修改了安全相关键。
// current 是库里现有的配置（config.GetAll 的结果），库里没有的键按默认值比较。
// 值与现有值相同不算修改：前端保存整张表单时，只改站点名不应要求 2FA。
// 打码占位值已在 stripMaskedSecrets 中删除，等同于未修改。
func sensitiveSettingsChanged(cfg, current map[string]interface{}) bool {
	for key, value := range cfg {
		if _, ok := sensitiveSettingKeys[key]; !ok {
			continue
		}
		existing, ok := current[key]
		if !ok {
			existing, ok = settingDefaults()[key]
		}
		if !ok || !reflect.DeepEqual(normalizeSettingValue(value), normalizeSettingValue(existing)) {
			return true
		}
	}
	return false
}

// adminRevealSecret 返回密钥类配置的明文。方法已标记为敏感操作：需要 2FA
// 或 10 分钟内的 step-up 窗口。每次读取都写审计日志。
func adminRevealSecret(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params struct {
		Key string `json:"key"`
	}
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid request body: "+err.Error(), nil)
	}
	if _, ok := secretSettingKeys[params.Key]; !ok {
		return nil, rpc.MakeError(rpc.InvalidParams, "unknown secret key", nil)
	}
	value, err := config.GetAs[string](params.Key, "")
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to read setting: "+err.Error(), nil)
	}
	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, "revealed secret setting: "+params.Key, "warn")
	return map[string]any{"key": params.Key, "value": value}, nil
}

// metricStoreConfigKeys 是与 metrics 独立数据库及 rollup 策略相关、需要
// 触发连接测试 + 热重载的配置键。
//
// 注意：metric_store_enabled 已废弃（metric store 始终启用），不再纳入此集合。
var metricStoreConfigKeys = map[string]struct{}{
	metricstore.MetricDBDriverKey:                         {},
	metricstore.MetricDBDSNKey:                            {},
	metricstore.MetricTablePrefixKey:                      {},
	metricstore.MetricMaxOpenConnsKey:                     {},
	metricstore.MetricMaxIdleConnsKey:                     {},
	metricstore.MetricRollupMinuteRetentionMinutesKey:     {},
	metricstore.MetricRollupFiveMinuteRetentionMinutesKey: {},
	metricstore.MetricRollupHourRetentionHoursKey:         {},
}

// metricKeysTouched 判断本次设置变更是否涉及 metrics 数据库相关键。
func metricKeysTouched(cfg map[string]interface{}) bool {
	for key := range cfg {
		if _, ok := metricStoreConfigKeys[key]; ok {
			return true
		}
	}
	return false
}

func adminEditSettings(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	cfg := make(map[string]interface{})
	if err := req.BindParams(&cfg); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid or missing request body: "+err.Error(), nil)
	}

	// 打码后的密钥原样回传时不能覆盖真实值；验证码字段只是校验用的临时字段。
	stripMaskedSecrets(cfg)
	twoFACode := takeSettingsTwoFactorCode(ctx, cfg)

	// 真正修改了认证/授权/注入相关配置时，需要敏感操作二次验证（或 10 分钟内的 step-up 窗口）。
	current, err := config.GetAll()
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to get settings: "+err.Error(), nil)
	}
	if sensitiveSettingsChanged(cfg, current) {
		if err := api.RequireSensitive2FAFromContext(ctx, twoFACode); err != nil {
			return nil, rpc.MakeError(rpc.PermissionDenied, err.Error(), nil)
		}
	}

	removeRetiredLowResourceMode(cfg)
	if err := validateMetricRollupSettingChanges(cfg); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}

	// 若本次修改涉及 metrics 数据库配置，则在落库前先用「当前配置 + 本次改动」
	// 合并出的目标配置做一次连接测试。metric store 始终启用，只要触及 metrics
	// 相关键就做连接测试，避免把明显无效的连接串保存给用户。
	touchedMetric := metricKeysTouched(cfg)
	if touchedMetric {
		// 数据库类型不再由前端显式选择，而是根据 DSN 自动推断后写回配置，
		// 使后续连接测试、热重载和初始化都使用一致的 driver。
		if v, ok := cfg[metricstore.MetricDBDSNKey]; ok {
			if dsn, ok := v.(string); ok {
				dsn = strings.TrimSpace(dsn)
				cfg[metricstore.MetricDBDSNKey] = dsn
				if driver, inferred := metricstore.InferDriverFromDSN(dsn); inferred {
					cfg[metricstore.MetricDBDriverKey] = string(driver)
				}
			}
		}

		merged, err := mergedMetricConfig(cfg)
		if err != nil {
			return nil, rpc.MakeError(rpc.InternalError, "Failed to resolve metric store config: "+err.Error(), nil)
		}
		testCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if err := metricstore.TestConnection(testCtx, merged); err != nil {
			cancel()
			return nil, rpc.MakeError(rpc.InvalidParams,
				"Metrics database connection test failed: "+err.Error(), nil)
		}
		cancel()
	}

	if err := config.SetMany(cfg); err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to update settings: "+err.Error(), nil)
	}

	// 配置已落库，热重载 metric store（无需重启）。旧结构必须在下一次
	// 启动前进入受限迁移页，不能在普通 HTTP 服务仍运行时切换路由。
	if touchedMetric {
		reloadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := metricstore.Reload(reloadCtx); err != nil {
			cancel()
			if errors.Is(err, metricstore.ErrStructureUpgradeRequired) {
				auditSettingsUpdate(ctx, cfg)
				lifecycle.RequestRestart(lifecycle.RestartForMetricStoreStructureUpgrade)
				return map[string]any{
					"restart_required": true,
					"guide_path":       "/admin/database-migration",
				}, nil
			}
			return nil, rpc.MakeError(rpc.InternalError,
				"Settings saved but metrics database hot reload failed: "+err.Error(), nil)
		}
		cancel()
	}

	auditSettingsUpdate(ctx, cfg)
	return nil, nil
}

func auditSettingsUpdate(ctx context.Context, cfg map[string]interface{}) {
	message := "update settings: "
	for key := range cfg {
		message += key + ", "
	}
	if len(message) > 2 {
		message = message[:len(message)-2]
	}
	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, message, "info")
}

// removeRetiredLowResourceMode keeps older admin clients from recreating its
// config row after the startup migration removes it.
func removeRetiredLowResourceMode(cfg map[string]interface{}) {
	delete(cfg, "low_resource_mode")
}

// mergedMetricConfig 读取当前持久化的 metric store 配置，并把本次请求中涉及的
// metrics 相关键覆盖上去，得到「即将生效」的目标配置，用于落库前的连接测试。
func mergedMetricConfig(cfg map[string]interface{}) (*metricstore.MetricStoreConfig, error) {
	merged, err := config.GetManyAs[metricstore.MetricStoreConfig]()
	if err != nil {
		return nil, err
	}

	if v, ok := cfg[metricstore.MetricDBDriverKey]; ok {
		if s, ok := v.(string); ok {
			merged.Driver = s
		}
	}

	if v, ok := cfg[metricstore.MetricDBDSNKey]; ok {
		if s, ok := v.(string); ok {
			merged.DSN = s
		}
	}
	if v, ok := cfg[metricstore.MetricTablePrefixKey]; ok {
		if s, ok := v.(string); ok {
			merged.TablePrefix = s
		}
	}
	if v, ok := cfg[metricstore.MetricMaxOpenConnsKey]; ok {
		merged.MaxOpenConns = toInt(v, merged.MaxOpenConns)
	}
	if v, ok := cfg[metricstore.MetricMaxIdleConnsKey]; ok {
		merged.MaxIdleConns = toInt(v, merged.MaxIdleConns)
	}
	if v, ok := cfg[metricstore.MetricRollupMinuteRetentionMinutesKey]; ok {
		merged.RollupMinuteRetentionMinutes = toInt(v, merged.RollupMinuteRetentionMinutes)
	}
	if v, ok := cfg[metricstore.MetricRollupFiveMinuteRetentionMinutesKey]; ok {
		merged.RollupFiveMinuteRetentionMinutes = toInt(v, merged.RollupFiveMinuteRetentionMinutes)
	}
	if v, ok := cfg[metricstore.MetricRollupHourRetentionHoursKey]; ok {
		merged.RollupHourRetentionHours = toInt(v, merged.RollupHourRetentionHours)
	}

	return merged, nil
}

func validateMetricRollupSettingChanges(cfg map[string]interface{}) error {
	keys := []string{
		metricstore.MetricRollupMinuteRetentionMinutesKey,
		metricstore.MetricRollupFiveMinuteRetentionMinutesKey,
		metricstore.MetricRollupHourRetentionHoursKey,
	}
	for _, key := range keys {
		value, ok := cfg[key]
		if !ok {
			continue
		}
		n, err := metricRollupSettingInt(value)
		if err != nil || n <= 0 {
			return fmt.Errorf("%s must be a positive integer", key)
		}
	}
	return nil
}

func metricRollupSettingInt(value any) (int, error) {
	maxInt := float64(^uint(0) >> 1)
	switch value := value.(type) {
	case int:
		return value, nil
	case int8:
		return int(value), nil
	case int16:
		return int(value), nil
	case int32:
		return int(value), nil
	case int64:
		if float64(value) > maxInt || float64(value) < -maxInt-1 {
			return 0, fmt.Errorf("integer overflow")
		}
		return int(value), nil
	case uint:
		if float64(value) > maxInt {
			return 0, fmt.Errorf("integer overflow")
		}
		return int(value), nil
	case uint8:
		return int(value), nil
	case uint16:
		return int(value), nil
	case uint32:
		if float64(value) > maxInt {
			return 0, fmt.Errorf("integer overflow")
		}
		return int(value), nil
	case uint64:
		if float64(value) > maxInt {
			return 0, fmt.Errorf("integer overflow")
		}
		return int(value), nil
	case float32:
		return metricRollupSettingInt(float64(value))
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value > maxInt || value < -maxInt-1 {
			return 0, fmt.Errorf("not an integer")
		}
		return int(value), nil
	case string:
		return strconv.Atoi(strings.TrimSpace(value))
	default:
		return 0, fmt.Errorf("unsupported numeric type")
	}
}

// toInt 将 JSON 解码得到的任意值（通常是 float64 或 string）转换为 int，失败时返回 fallback。
func toInt(v any, fallback int) int {

	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case int64:
		return int(val)
	case string:
		if n, err := strconv.Atoi(val); err == nil {
			return n
		}
	}
	return fallback
}

func adminClearAllRecords(ctx context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {

	records.DeleteAll()
	tasks.DeleteAllPingRecords()
	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, "clear all records", "info")
	return nil, nil
}

func adminOrderClients(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var order map[string]int
	if err := req.BindParams(&order); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid or missing request body: "+err.Error(), nil)
	}
	db := dbcore.GetDBInstance()
	for uuid, weight := range order {
		if err := db.Model(&models.Client{}).Where("uuid = ?", uuid).Update("weight", weight).Error; err != nil {
			return nil, rpc.MakeError(rpc.InternalError, "Failed to update client weight: "+err.Error(), nil)
		}
	}
	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, "order clients", "info")
	return nil, nil
}
