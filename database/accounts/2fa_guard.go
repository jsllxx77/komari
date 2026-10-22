package accounts

// 2fa_guard.go
// TOTP 校验的加固层：按用户限制失败次数、记录已使用的时间窗防止重放。
// 登录、OAuth 第二步、敏感操作、启用 2FA 都应通过这里校验，而不是直接调用
// totp.Validate —— 后者既不限速也不防重放，6 位验证码可以被全速穷举。

import (
	"errors"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// totpPeriodSeconds 与 authenticator 应用使用的步长一致。
	totpPeriodSeconds = 30
	// totpMaxFailures 是在一个窗口内允许的失败次数，达到后锁定。
	totpMaxFailures = 5
	// totpFailureWindow 是失败计数的统计窗口。
	totpFailureWindow = 5 * time.Minute
	// totpLockoutDuration 是达到上限后的锁定时长。
	totpLockoutDuration = 5 * time.Minute
	// totpGuardMaxEntries 限制内存里跟踪的用户数，避免被大量不同账号撑爆。
	totpGuardMaxEntries = 10_000
)

var (
	// ErrTooMany2FAAttempts 表示该用户连续失败过多，暂时不接受任何验证码。
	ErrTooMany2FAAttempts = errors.New("too many 2FA attempts, please try again later")
	// Err2FAReplay 表示这个验证码在当前时间窗内已经成功使用过。
	Err2FAReplay = errors.New("2FA code has already been used")
	// ErrTwoFactorAlreadyEnabled 表示账号已经启用 2FA，不允许直接覆盖密钥。
	ErrTwoFactorAlreadyEnabled = errors.New("2FA is already enabled for this account")
)

type totpFailure struct {
	count int
	// pending 是已经预占、正在校验中的次数。检查与预占在同一把锁里完成，
	// 并发提交的错码因此最多被校验 totpMaxFailures 次。
	pending int
	last    time.Time
}

// totpAttemptGuard 保存每个调用主体的失败计数和已使用的时间窗。
// 状态只在内存里：进程重启后最多允许重放一个时间窗，这是可以接受的折中。
type totpAttemptGuard struct {
	mu       sync.Mutex
	failures map[string]totpFailure
	lastStep map[string]int64
}

var totpGuard = &totpAttemptGuard{
	failures: make(map[string]totpFailure),
	lastStep: make(map[string]int64),
}

// reserve 在同一把锁里检查锁定状态并预占一次校验名额。
// 已失败次数加上正在校验的次数达到上限时返回 false：以前是"先查是否锁定、
// 校验完再记失败"，并发提交的错码会全部被校验，锁定形同虚设。
// 返回 true 时调用方必须在校验结束后调用 release。
func (g *totpAttemptGuard) reserve(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	entry := g.failures[key]
	if entry.count >= totpMaxFailures {
		if now.Sub(entry.last) >= totpLockoutDuration {
			entry.count = 0
		}
	} else if entry.count > 0 && now.Sub(entry.last) >= totpFailureWindow {
		entry.count = 0
	}
	if entry.count+entry.pending >= totpMaxFailures {
		return false
	}
	entry.pending++
	if entry.last.IsZero() {
		entry.last = now
	}
	g.failures[key] = entry
	g.cleanupLocked(now)
	return true
}

// release 结束一次预占：failed 为 true 时把预占转为一次失败，
// success 为 true 时清空失败计数；两者都为 false（例如查库出错）只归还名额。
func (g *totpAttemptGuard) release(key string, now time.Time, failed, success bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, ok := g.failures[key]
	if !ok {
		return
	}
	if entry.pending > 0 {
		entry.pending--
	}
	switch {
	case failed:
		entry.count++
		entry.last = now
	case success:
		entry.count = 0
	}
	if entry.count == 0 && entry.pending == 0 {
		delete(g.failures, key)
		return
	}
	g.failures[key] = entry
}

// claimStep 记录并占用一个时间窗；已用过（或更早）的时间窗返回 false。
func (g *totpAttemptGuard) claimStep(key string, step int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if last, ok := g.lastStep[key]; ok && step <= last {
		return false
	}
	g.lastStep[key] = step
	return true
}

// forget 清空某个 key 的全部状态（停用/更换 2FA 时调用）。
func (g *totpAttemptGuard) forget(key string) {
	g.resetWithUsedStep(key, 0)
}

// resetWithUsedStep 清空 key 的状态，并把 usedStep（大于 0 时）记为已使用。
// 两步在同一把锁里完成，中间不会出现"状态已清空、时间窗尚未占用"的空档。
func (g *totpAttemptGuard) resetWithUsedStep(key string, usedStep int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.failures, key)
	delete(g.lastStep, key)
	if usedStep > 0 {
		g.lastStep[key] = usedStep
	}
}

// cleanupLocked 在表过大时清理过期条目，保证内存占用有上界。
func (g *totpAttemptGuard) cleanupLocked(now time.Time) {
	if len(g.failures) <= totpGuardMaxEntries && len(g.lastStep) <= totpGuardMaxEntries {
		return
	}
	for key, entry := range g.failures {
		if entry.pending == 0 && now.Sub(entry.last) >= totpLockoutDuration {
			delete(g.failures, key)
		}
	}
	if excess := len(g.lastStep) - totpGuardMaxEntries; excess > 0 {
		for key := range g.lastStep {
			if excess <= 0 {
				break
			}
			delete(g.lastStep, key)
			excess--
		}
	}
}

// totpStepMatcher 是实际执行 TOTP 比对的函数。测试会替换它来统计真正被校验的次数。
var totpStepMatcher = matchTotpStep

// matchTotpStep 在 now 的前后各一个时间窗内查找匹配的验证码，返回命中的时间窗。
func matchTotpStep(secret, code string, now time.Time) (int64, bool) {
	if secret == "" || code == "" {
		return 0, false
	}
	current := now.Unix() / totpPeriodSeconds
	for _, offset := range []int64{0, -1, 1} {
		candidate := current + offset
		at := time.Unix(candidate*totpPeriodSeconds, 0).UTC()
		ok, err := totp.ValidateCustom(code, secret, at, totp.ValidateOpts{
			Period:    totpPeriodSeconds,
			Skew:      0,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err == nil && ok {
			return candidate, true
		}
	}
	return 0, false
}

// Verify2FaStrict 校验用户的 TOTP 验证码，并附带限速与防重放。
// 返回 ErrTooMany2FAAttempts 表示该用户已被锁定；返回 Err2FAReplay 表示验证码
// 已被使用过。用户未启用 2FA 时返回 (false, nil)。
func Verify2FaStrict(userUUID, code string) (bool, error) {
	if userUUID == "" || code == "" {
		return false, nil
	}
	key := "user:" + userUUID
	now := time.Now().UTC()
	// 先预占名额再查库、校验：并发的错码不会越过失败上限。
	if !totpGuard.reserve(key, now) {
		return false, ErrTooMany2FAAttempts
	}

	user, err := GetUserByUUID(userUUID)
	if err != nil {
		totpGuard.release(key, now, false, false)
		return false, err
	}
	if user.TwoFactor == "" {
		totpGuard.release(key, now, false, false)
		return false, nil
	}

	step, ok := totpStepMatcher(user.TwoFactor, code, now)
	if !ok {
		totpGuard.release(key, now, true, false)
		return false, nil
	}
	if !totpGuard.claimStep(key, step) {
		totpGuard.release(key, now, true, false)
		return false, Err2FAReplay
	}
	totpGuard.release(key, now, false, true)
	return true, nil
}

// Validate2FACodeForSecret 校验验证码是否匹配一个尚未入库的密钥（启用 2FA 时
// 的待启用密钥）。失败次数按 ownerKey 计数，避免用同一个入口穷举。
// 校验通过时返回命中的时间窗，启用后应把它记为已使用（见 Enable2FaIfDisabled），
// 防止同一个验证码在启用后被再用一次。
func Validate2FACodeForSecret(ownerKey, secret, code string) (int64, bool, error) {
	if ownerKey == "" || secret == "" || code == "" {
		return 0, false, nil
	}
	key := "pending:" + ownerKey
	now := time.Now().UTC()
	if !totpGuard.reserve(key, now) {
		return 0, false, ErrTooMany2FAAttempts
	}
	step, ok := totpStepMatcher(secret, code, now)
	if !ok {
		totpGuard.release(key, now, true, false)
		return 0, false, nil
	}
	totpGuard.release(key, now, false, true)
	return step, true, nil
}

// Forget2FAState 清除某个用户的失败计数与防重放状态。
// 停用或更换 2FA 密钥后必须调用，否则旧的失败计数会继续生效。
func Forget2FAState(userUUID string) {
	forget2FAStateWithUsedStep(userUUID, 0)
}

// forget2FAStateWithUsedStep 清除状态，并把 usedStep（大于 0 时）记为该用户
// 已使用过的时间窗。
func forget2FAStateWithUsedStep(userUUID string, usedStep int64) {
	if userUUID == "" {
		return
	}
	totpGuard.resetWithUsedStep("user:"+userUUID, usedStep)
	totpGuard.forget("pending:" + userUUID)
}
