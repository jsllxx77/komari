package accounts

import (
	"bytes"
	"sync/atomic"
	"testing"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"golang.org/x/crypto/bcrypt"
)

// TestDummyPasswordHashIsFixedCostBcrypt 确认 dummy 哈希是合法的 bcrypt 哈希，
// 且成本与项目其它哈希一致（DefaultCost），从而保证补时操作的成本固定。
func TestDummyPasswordHashIsFixedCostBcrypt(t *testing.T) {
	hash := dummyPasswordHash()
	if len(hash) == 0 {
		t.Fatal("dummy password hash is empty")
	}
	if !isBcryptHash(string(hash)) {
		t.Fatalf("dummy hash %q is not a bcrypt hash", hash)
	}
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		t.Fatalf("bcrypt.Cost(dummy) error: %v", err)
	}
	if cost != bcrypt.DefaultCost {
		t.Fatalf("dummy hash cost = %d, want DefaultCost %d", cost, bcrypt.DefaultCost)
	}
}

// withDummyBcryptSpy 临时替换包级 verifyDummyBcrypt，记录调用次数与最近一次
// 输入，测试结束后恢复原实现。
func withDummyBcryptSpy(t *testing.T) (calls *int32, lastInput *[]byte) {
	t.Helper()
	original := verifyDummyBcrypt
	var n int32
	var input []byte
	verifyDummyBcrypt = func(in []byte) {
		atomic.AddInt32(&n, 1)
		input = append([]byte(nil), in...)
	}
	t.Cleanup(func() { verifyDummyBcrypt = original })
	return &n, &input
}

// TestLegacyHashPathPaysDummyBcrypt 是 F-26 的核心回归测试：旧 SHA-256 哈希
// 账号无论密码对错，走完校验都必须额外执行一次 dummy bcrypt；升级为 bcrypt
// 账号后则由真实 bcrypt 承担成本，不应再走 dummy 路径。
func TestLegacyHashPathPaysDummyBcrypt(t *testing.T) {
	legacy := models.User{
		UUID:     "legacy-timing-uuid",
		Username: "legacy-timing-user",
		Passwd:   legacyHashPasswd("Old-password1"),
	}
	if err := dbcore.GetDBInstance().Create(&legacy).Error; err != nil {
		t.Fatalf("create legacy user: %v", err)
	}
	t.Cleanup(func() { _ = DeleteAccountByUsername("legacy-timing-user") })

	calls, lastInput := withDummyBcryptSpy(t)

	// 密码错误：旧哈希分支仍然要付出一次 bcrypt 成本。
	if _, ok := CheckPassword("legacy-timing-user", "wrong-password"); ok {
		t.Fatal("wrong password accepted for legacy hash")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("legacy wrong-password path called dummy bcrypt %d times, want 1", got)
	}
	if want := prehashPasswd("wrong-password"); !bytes.Equal(*lastInput, want) {
		t.Fatalf("dummy bcrypt received %q, want prehash %q", *lastInput, want)
	}

	// 密码正确：仍需先补一次 dummy bcrypt（随后才升级哈希）。
	atomic.StoreInt32(calls, 0)
	if _, ok := CheckPassword("legacy-timing-user", "Old-password1"); !ok {
		t.Fatal("correct password rejected for legacy hash")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("legacy correct-password path called dummy bcrypt %d times, want 1", got)
	}

	// 升级后变成 bcrypt 账号，真实 bcrypt 已承担成本，不应再走 dummy。
	atomic.StoreInt32(calls, 0)
	if _, ok := CheckPassword("legacy-timing-user", "Old-password1"); !ok {
		t.Fatal("password rejected after upgrade")
	}
	if got := atomic.LoadInt32(calls); got != 0 {
		t.Fatalf("bcrypt account called dummy bcrypt %d times, want 0", got)
	}
}

// TestUnknownUserPaysDummyBcrypt 确认“用户不存在”路径同样使用统一的 dummy
// bcrypt 兜底，与旧哈希账号路径保持一致。
func TestUnknownUserPaysDummyBcrypt(t *testing.T) {
	calls, _ := withDummyBcryptSpy(t)
	if _, ok := CheckPassword("no-such-user-for-timing", "whatever-password"); ok {
		t.Fatal("unknown user accepted")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("unknown-user path called dummy bcrypt %d times, want 1", got)
	}
}
