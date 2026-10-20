package client

import (
	"net"
	"unicode/utf8"

	"github.com/komari-monitor/komari/database/clients"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/utils/geoip"
)

// agentBasicInfoStringFields 列出 agent 可以上报的字符串字段及其最大字节数
// （与 models.Client 上的 varchar 长度一致）。不在名单里的字段一律丢弃：
// agent.basicInfo 的 info 是任意 map，若原样写库，节点就能改自己的
// expired_at、traffic_limit、price、hidden、token 等管理员字段。
var agentBasicInfoStringFields = map[string]int{
	"cpu_name":       100,
	"virtualization": 50,
	"arch":           50,
	"os":             100,
	"kernel_version": 100,
	"gpu_name":       100,
	"ipv4":           100,
	"ipv6":           100,
	"version":        100,
}

// agentBasicInfoNumberFields 列出 agent 可以上报的数值字段，取值范围仍由
// clients.SaveClientInfo 校验。
var agentBasicInfoNumberFields = map[string]struct{}{
	"cpu_cores":          {},
	"cpu_physical_cores": {},
	"mem_total":          {},
	"swap_total":         {},
	"disk_total":         {},
}

// sanitizeAgentBasicInfo 只保留 agent 允许上报的字段，并截断超长字符串。
// region 不在名单里：它由服务端根据 GeoIP 计算后写入，不接受上报值。
func sanitizeAgentBasicInfo(info map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(info))
	for key, value := range info {
		if limit, ok := agentBasicInfoStringFields[key]; ok {
			text, ok := value.(string)
			if !ok {
				continue
			}
			out[key] = truncateAgentString(text, limit)
			continue
		}
		if _, ok := agentBasicInfoNumberFields[key]; ok {
			out[key] = value
		}
	}
	return out
}

// truncateAgentString 按字节上限截断，并保证不会切在多字节字符中间。
func truncateAgentString(value string, max int) string {
	if len(value) <= max {
		return value
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

func getClientIPType(ip net.IP) int {
	// 0:ipv4 1:ipv6 -1:错误的输入
	if ip == nil {
		return -1
	}
	if ip.To4() == nil {
		return 1
	} else {
		return 0
	}
}

func saveClientBasicInfo(info map[string]interface{}, uuid string, fallbackIP string) error {
	// 白名单必须在补 uuid / region 之前执行，避免上报值混进管理员字段。
	info = sanitizeAgentBasicInfo(info)
	info["uuid"] = uuid
	applyFallbackClientIP(info, fallbackIP)
	appendClientRegionFromGeoIP(info)
	return clients.SaveClientInfo(info)
}

func applyFallbackClientIP(info map[string]interface{}, fallbackIP string) {
	if hasClientIP(info) {
		return
	}
	ip := net.ParseIP(fallbackIP)

	switch getClientIPType(ip) {
	case 0:
		info["ipv4"] = fallbackIP
	case 1:
		info["ipv6"] = fallbackIP
	}
}

func hasClientIP(info map[string]interface{}) bool {
	if ipv4, ok := info["ipv4"].(string); ok && ipv4 != "" {
		return true
	}
	if ipv6, ok := info["ipv6"].(string); ok && ipv6 != "" {
		return true
	}
	return false
}

func appendClientRegionFromGeoIP(info map[string]interface{}) {
	cfg, err := config.GetAs[bool](config.GeoIpEnabledKey)
	if err != nil || !cfg {
		return
	}

	for _, key := range []string{"ipv4", "ipv6"} {
		ipStr, ok := info[key].(string)
		if !ok || ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		record, _ := geoip.GetGeoInfo(ip)
		if record == nil {
			continue
		}
		region := geoip.GetRegionUnicodeEmoji(record.ISOCode)
		if region == "" {
			continue
		}
		info["region"] = region
		return
	}
}
