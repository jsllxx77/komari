package public

import (
	"net"
	"sync"
	"time"
)

const (
	// loginFailureLimit 是同一来源地址在一个窗口内允许的失败登录次数。
	loginFailureLimit = 10
	// loginFailureWindow 是失败计数的统计窗口，达到上限后该地址需等待窗口结束。
	loginFailureWindow = 15 * time.Minute
	// loginLimiterMaxEntries 限制跟踪的地址数量，避免大量来源地址耗尽内存。
	loginLimiterMaxEntries = 100_000
)

// loginLimiter 按来源地址限制失败的密码登录。
//
// 只统计失败次数，且登录成功会清空该地址的计数，因此攻击者从其他地址爆破
// 不会把管理员自己锁在外面。IPv6 地址按 /64 前缀归并，因为单台主机通常
// 可以任意使用整个 /64。
type loginLimiter struct {
	mu          sync.Mutex
	limit       int
	window      time.Duration
	maxEntries  int
	entries     map[string]*loginFailures
	lastCleanup time.Time
}

type loginFailures struct {
	count int
	start time.Time
}

func newLoginLimiter(limit int, window time.Duration, maxEntries int) *loginLimiter {
	return &loginLimiter{
		limit:      limit,
		window:     window,
		maxEntries: maxEntries,
		entries:    make(map[string]*loginFailures),
	}
}

var loginAttempts = newLoginLimiter(loginFailureLimit, loginFailureWindow, loginLimiterMaxEntries)

// Allow 报告该地址当前是否允许尝试登录；被拒绝时返回需要等待的时长。
func (l *loginLimiter) Allow(ip string, now time.Time) (bool, time.Duration) {
	key := loginLimiterKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entries[key]
	if entry == nil {
		return true, 0
	}
	if now.Sub(entry.start) >= l.window {
		delete(l.entries, key)
		return true, 0
	}
	if entry.count >= l.limit {
		return false, entry.start.Add(l.window).Sub(now)
	}
	return true, 0
}

// Fail 记录一次失败登录，返回该地址是否因此刚好达到上限。
func (l *loginLimiter) Fail(ip string, now time.Time) bool {
	key := loginLimiterKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entries[key]
	if entry == nil || now.Sub(entry.start) >= l.window {
		if entry == nil && len(l.entries) >= l.maxEntries {
			l.cleanupLocked(now)
			if len(l.entries) >= l.maxEntries {
				return false
			}
		}
		entry = &loginFailures{start: now}
		l.entries[key] = entry
	}
	entry.count++
	if now.Sub(l.lastCleanup) >= l.window {
		l.cleanupLocked(now)
	}
	return entry.count == l.limit
}

// Reset 在登录成功后清除该地址的失败计数。
func (l *loginLimiter) Reset(ip string) {
	key := loginLimiterKey(ip)
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

func (l *loginLimiter) cleanupLocked(now time.Time) {
	for key, entry := range l.entries {
		if now.Sub(entry.start) >= l.window {
			delete(l.entries, key)
		}
	}
	l.lastCleanup = now
}

// loginLimiterKey 将 IPv4 地址原样作为键，IPv6 地址归并到 /64 前缀。
func loginLimiterKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
