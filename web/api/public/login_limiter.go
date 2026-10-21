package public

import (
	"net"
	"sync"
	"time"
)

const (
	// loginFailureLimit 是同一来源地址、同一 (来源地址, 用户名) 在一个窗口内
	// 允许的失败登录次数。
	loginFailureLimit = 10
	// loginFailureWindow 是失败计数的统计窗口，达到上限后需等待窗口结束。
	loginFailureWindow = 15 * time.Minute
	// loginLimiterMaxEntries 限制跟踪的键数量，避免大量来源地址耗尽内存。
	loginLimiterMaxEntries = 100_000
	// loginUsernameDelayThreshold 是用户名维度开始延迟响应的失败次数阈值。
	loginUsernameDelayThreshold = 20
	// loginUsernameDelayStep 是超过阈值后每多一次失败增加的延迟。
	loginUsernameDelayStep = time.Second
	// loginUsernameMaxDelay 是用户名维度延迟的上限。
	loginUsernameMaxDelay = 5 * time.Second
)

// loginFailures 记录某个限流键在一个窗口内的失败次数和正在进行中的尝试。
//
// count 是已经确认失败的次数，pending 是已经通过 Begin 预占、但尚未确认结果
// 的尝试数。检查 count+pending 是否达到上限，可保证并发请求也不会超过配额。
type loginFailures struct {
	count   int
	pending int
	start   time.Time
}

// loginLimiter 按 IP、用户名和 (IP, 用户名) 三个维度限制失败的密码登录。
//
// IP 与 (IP, 用户名) 维度是硬锁：达到上限后直接拒绝。用户名维度不做硬锁，
// 只随失败次数增加响应延迟，避免攻击者故意把管理员锁死。IPv6 地址按 /64
// 前缀归并，因为单台主机通常可以任意使用整个 /64。
type loginLimiter struct {
	mu         sync.Mutex
	limit      int
	window     time.Duration
	maxEntries int

	// entries 保存所有有独立配额的键，键带维度前缀避免不同维度互相覆盖。
	entries map[string]*loginFailures
	// overflow 保存表满后新键共享的桶，按维度区分，所有新键共用统一配额。
	overflow map[string]*loginFailures

	// 用户名维度的延迟参数，测试可直接调整。
	delayThreshold int
	delayStep      time.Duration
	maxDelay       time.Duration

	lastCleanup time.Time
}

// loginReservation 是一次已预占配额的登录尝试，必须用 ConfirmFailure、
// ConfirmSuccess 或 Cancel 收尾，否则 pending 会一直占用配额。
type loginReservation struct {
	ipEntry     *loginFailures
	ipUserEntry *loginFailures
	ipKey       string
	ipUserKey   string
	username    string
}

func newLoginLimiter(limit int, window time.Duration, maxEntries int) *loginLimiter {
	return &loginLimiter{
		limit:          limit,
		window:         window,
		maxEntries:     maxEntries,
		entries:        make(map[string]*loginFailures),
		overflow:       make(map[string]*loginFailures),
		delayThreshold: loginUsernameDelayThreshold,
		delayStep:      loginUsernameDelayStep,
		maxDelay:       loginUsernameMaxDelay,
	}
}

var loginAttempts = newLoginLimiter(loginFailureLimit, loginFailureWindow, loginLimiterMaxEntries)

// Begin 原子地检查三个维度并预占配额。检查与自增在同一把锁内完成，因此并发
// 请求也不会超过上限。返回的 reservation 必须由调用方收尾。
func (l *loginLimiter) Begin(ip, username string, now time.Time) (bool, time.Duration, *loginReservation) {
	ipKey := ipLimiterKey(ip)
	ipUserKey := ipUserLimiterKey(ip, username)

	l.mu.Lock()
	defer l.mu.Unlock()

	ipEntry := l.entryLocked(ipKey, "ip", now)
	if retryAfter, blocked := l.blockedRetryLocked(ipEntry, now); blocked {
		return false, retryAfter, nil
	}
	ipUserEntry := l.entryLocked(ipUserKey, "ipuser", now)
	if retryAfter, blocked := l.blockedRetryLocked(ipUserEntry, now); blocked {
		return false, retryAfter, nil
	}

	ipEntry.pending++
	ipUserEntry.pending++
	return true, 0, &loginReservation{
		ipEntry:     ipEntry,
		ipUserEntry: ipUserEntry,
		ipKey:       ipKey,
		ipUserKey:   ipUserKey,
		username:    username,
	}
}

// ConfirmFailure 确认一次失败尝试：释放预占并把失败计数加一。返回是否有硬锁
// 维度因此刚好达到上限（用于审计日志）。
func (l *loginLimiter) ConfirmFailure(res *loginReservation, now time.Time) bool {
	if res == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	hitLimit := false
	for _, entry := range []*loginFailures{res.ipEntry, res.ipUserEntry} {
		if entry == nil {
			continue
		}
		if entry.pending > 0 {
			entry.pending--
		}
		entry.count++
		if entry.count == l.limit {
			hitLimit = true
		}
	}
	l.countUsernameFailureLocked(res.username, now)
	return hitLimit
}

// ConfirmSuccess 确认一次成功尝试：释放预占并清除该 (IP, 用户名) 及用户名的
// 失败计数，避免正常用户被此前的输错密码拖累。
func (l *loginLimiter) ConfirmSuccess(res *loginReservation, _ time.Time) {
	if res == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.releaseLocked(res.ipKey, res.ipEntry)
	l.releaseLocked(res.ipUserKey, res.ipUserEntry)

	if res.username == "" {
		return
	}
	key := usernameLimiterKey(res.username)
	if entry, ok := l.entries[key]; ok && entry.pending == 0 {
		delete(l.entries, key)
	}
}

// Cancel 释放预占但不计入失败，用于与密码无关的中断路径（例如读取账号失败）。
func (l *loginLimiter) Cancel(res *loginReservation) {
	if res == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, entry := range []*loginFailures{res.ipEntry, res.ipUserEntry} {
		if entry != nil && entry.pending > 0 {
			entry.pending--
		}
	}
}

// FailureDelay 返回该用户名当前应附加的响应延迟。<= 阈值返回 0，之后线性增长
// 并在 maxDelay 处封顶。
func (l *loginLimiter) FailureDelay(username string, now time.Time) time.Duration {
	if username == "" {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	var entry *loginFailures
	key := usernameLimiterKey(username)
	if tracked, ok := l.entries[key]; ok && now.Sub(tracked.start) < l.window {
		entry = tracked
	} else if len(l.entries) >= l.maxEntries {
		// 表满时用户名维度也使用共享桶，保证新用户名仍被统一降速。
		if overflow, ok := l.overflow["user"]; ok && now.Sub(overflow.start) < l.window {
			entry = overflow
		}
	}
	if entry == nil || entry.count <= l.delayThreshold {
		return 0
	}
	delay := time.Duration(entry.count-l.delayThreshold) * l.delayStep
	if delay > l.maxDelay {
		return l.maxDelay
	}
	return delay
}

// countUsernameFailureLocked 只统计用户名维度的失败次数（不预占、不硬锁）。
func (l *loginLimiter) countUsernameFailureLocked(username string, now time.Time) {
	if username == "" {
		return
	}
	entry := l.entryLocked(usernameLimiterKey(username), "user", now)
	entry.count++
}

// releaseLocked 释放一次预占；仅对独占条目清空失败计数，共享 overflow 桶不
// 因单个成功登录而整体清零。
func (l *loginLimiter) releaseLocked(key string, entry *loginFailures) {
	if entry == nil {
		return
	}
	if entry.pending > 0 {
		entry.pending--
	}
	if l.entries[key] == entry {
		entry.count = 0
	}
}

// blockedRetryLocked 报告条目是否已无配额，并给出需要等待的时长。
func (l *loginLimiter) blockedRetryLocked(entry *loginFailures, now time.Time) (time.Duration, bool) {
	if entry == nil {
		return 0, false
	}
	if entry.count+entry.pending < l.limit {
		return 0, false
	}
	retryAfter := entry.start.Add(l.window).Sub(now)
	if retryAfter < 0 {
		retryAfter = 0
	}
	return retryAfter, true
}

// entryLocked 返回 key 对应的条目，必要时创建。表满时返回该维度共享的 overflow
// 桶，从而让所有新键共同降速而不是直接放行。
func (l *loginLimiter) entryLocked(key, dimension string, now time.Time) *loginFailures {
	if entry, ok := l.entries[key]; ok {
		if entry.pending == 0 && now.Sub(entry.start) >= l.window {
			delete(l.entries, key)
		} else {
			return entry
		}
	}
	if len(l.entries) >= l.maxEntries {
		l.cleanupLocked(now)
	}
	if len(l.entries) < l.maxEntries {
		entry := &loginFailures{start: now}
		l.entries[key] = entry
		return entry
	}
	overflow := l.overflow[dimension]
	if overflow == nil || (overflow.pending == 0 && now.Sub(overflow.start) >= l.window) {
		overflow = &loginFailures{start: now}
		l.overflow[dimension] = overflow
	}
	return overflow
}

func (l *loginLimiter) cleanupLocked(now time.Time) {
	for key, entry := range l.entries {
		if entry.pending == 0 && now.Sub(entry.start) >= l.window {
			delete(l.entries, key)
		}
	}
	for dimension, entry := range l.overflow {
		if entry.pending == 0 && now.Sub(entry.start) >= l.window {
			delete(l.overflow, dimension)
		}
	}
	l.lastCleanup = now
}

// Allow 报告该地址当前是否允许尝试登录；被拒绝时返回需要等待的时长。
//
// 这是单维度（仅 IP）的兼容接口，保留给旧调用方和既有测试；新代码应使用
// Begin/ConfirmFailure/ConfirmSuccess 以获得跨维度原子判定。
func (l *loginLimiter) Allow(ip string, now time.Time) (bool, time.Duration) {
	key := ipLimiterKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := l.peekLocked(key, now)
	if entry == nil && len(l.entries) >= l.maxEntries {
		if overflow, ok := l.overflow["ip"]; ok && now.Sub(overflow.start) < l.window {
			entry = overflow
		}
	}
	retryAfter, blocked := l.blockedRetryLocked(entry, now)
	if blocked {
		return false, retryAfter
	}
	return true, 0
}

// Fail 记录一次失败登录，返回该地址是否因此刚好达到上限。兼容接口，见 Allow。
func (l *loginLimiter) Fail(ip string, now time.Time) bool {
	key := ipLimiterKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := l.entryLocked(key, "ip", now)
	entry.count++
	if now.Sub(l.lastCleanup) >= l.window {
		l.cleanupLocked(now)
	}
	return entry.count == l.limit
}

// Reset 在登录成功后清除该地址的失败计数。兼容接口，见 Allow。
func (l *loginLimiter) Reset(ip string) {
	key := ipLimiterKey(ip)
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

// peekLocked 返回一个尚未过期的条目，过期条目会被删除；不会创建新条目。
func (l *loginLimiter) peekLocked(key string, now time.Time) *loginFailures {
	entry, ok := l.entries[key]
	if !ok {
		return nil
	}
	if entry.pending == 0 && now.Sub(entry.start) >= l.window {
		delete(l.entries, key)
		return nil
	}
	return entry
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

func ipLimiterKey(ip string) string {
	return "ip:" + loginLimiterKey(ip)
}

func ipUserLimiterKey(ip, username string) string {
	return "ipuser:" + loginLimiterKey(ip) + "\x00" + username
}

func usernameLimiterKey(username string) string {
	return "user:" + username
}
