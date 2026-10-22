package jsonrpc

// ratelimit.go
// F-08：/api/rpc2 与公开的 /api/records/* 对匿名访客做按 IP 的令牌桶限速，
// 防止单个来源用匿名批量或高频查询压满 CPU/内存。已认证调用方不受此限制
// （它们本来就有账号/密钥，滥用可追责，且前端管理页会并发查询）。

import (
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/pkg/rpc"
	"github.com/komari-monitor/komari/web/api"
)

const (
	// anonymousRPCBurst 是匿名来源可瞬时突发的请求数。
	anonymousRPCBurst = 30
	// anonymousRPCRatePerSecond 是每个匿名来源的持续补充速率。
	anonymousRPCRatePerSecond = 10
)

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// anonymousRateLimiter 是按 IP 的令牌桶集合。桶数量有上限，超过后按全局桶
// 统一限速，避免攻击者用海量源地址把表撑爆（对应 F-11 的同类问题）。
type anonymousRateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*tokenBucket
	overflow  *tokenBucket
	lastSweep time.Time
	maxIPs    int
}

var anonRateLimiter = &anonymousRateLimiter{
	buckets:  make(map[string]*tokenBucket),
	overflow: &tokenBucket{tokens: anonymousRPCBurst, last: time.Now()},
	maxIPs:   10000,
}

// rateLimitKey 返回 IP 对应的限速桶键。IPv6 按 /64 分桶：同一用户通常拥有
// 整个 /64，按 /128 分桶既挡不住单一来源，又很容易把桶表灌满。
func rateLimitKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return ip
	}
	return prefix.String()
}

// allow 消耗 n 个令牌；不足时返回 false。
func (l *anonymousRateLimiter) allow(ip string, n int) bool {
	if n <= 0 {
		n = 1
	}
	key := rateLimitKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.sweepLocked(now)

	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= l.maxIPs {
			// 表满：不再给新地址单独开桶，统一走共享桶降速。
			b = l.overflow
		} else {
			b = &tokenBucket{tokens: anonymousRPCBurst, last: now}
			l.buckets[key] = b
		}
	}
	// 按经过时间补充令牌。
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * anonymousRPCRatePerSecond
		if b.tokens > anonymousRPCBurst {
			b.tokens = anonymousRPCBurst
		}
		b.last = now
	}
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// sweepLocked 清掉长时间空闲的桶，防止内存无界增长。调用方需持锁。
func (l *anonymousRateLimiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < 5*time.Minute {
		return
	}
	l.lastSweep = now
	for ip, b := range l.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			delete(l.buckets, ip)
		}
	}
}

// charge 供 RPC 分发入口为批量请求追加扣减令牌（每条请求一个令牌）。
func (l *anonymousRateLimiter) charge(ip string, n int) bool {
	if n <= 0 {
		return true
	}
	return l.allow(ip, n)
}

// AnonymousRateLimit 是 gin 中间件：匿名来源每个请求先扣一个令牌，
// 超限返回 429。批量请求的额外令牌在 servePost 里按实际条数扣减。
func AnonymousRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := api.GetPrincipal(c)
		if p != nil && p.Type != rpc.PrincipalAnonymous {
			c.Next()
			return
		}
		if !anonRateLimiter.allow(c.ClientIP(), 1) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"status":  "error",
				"message": "Too many requests, please slow down.",
			})
			return
		}
		c.Next()
	}
}
