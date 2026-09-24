package accounts

import (
	"os"
	"strings"
	"testing"

	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
)

func TestMain(m *testing.M) {
	flags.DatabaseType = flags.DatabaseTypeSQLite
	flags.DatabaseFile = "file:database_accounts_test?mode=memory&cache=shared"

	db := dbcore.GetDBInstance()
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}

	os.Exit(m.Run())
}

func storedPasswd(t *testing.T, username string) string {
	t.Helper()
	var user models.User
	if err := dbcore.GetDBInstance().Where("username = ?", username).First(&user).Error; err != nil {
		t.Fatalf("load user %q: %v", username, err)
	}
	return user.Passwd
}

func TestCreateAccountStoresBcryptHash(t *testing.T) {
	user, err := CreateAccount("bcrypt-user", "Secret-password1")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() { _ = DeleteAccountByUsername("bcrypt-user") })

	if stored := storedPasswd(t, "bcrypt-user"); !isBcryptHash(stored) {
		t.Fatalf("stored hash %q is not bcrypt", stored)
	}
	if uuid, ok := CheckPassword("bcrypt-user", "Secret-password1"); !ok || uuid != user.UUID {
		t.Fatalf("CheckPassword(correct) = %q, %v", uuid, ok)
	}
	if _, ok := CheckPassword("bcrypt-user", "wrong-password"); ok {
		t.Fatal("CheckPassword accepted a wrong password")
	}
	if _, ok := CheckPassword("missing-user", "Secret-password1"); ok {
		t.Fatal("CheckPassword accepted an unknown user")
	}
}

func TestLongPasswordsBeyondBcryptLimit(t *testing.T) {
	long := strings.Repeat("长密码", 80) // 720 bytes, well past bcrypt's 72-byte limit
	if _, err := CreateAccount("long-password-user", long); err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() { _ = DeleteAccountByUsername("long-password-user") })

	if _, ok := CheckPassword("long-password-user", long); !ok {
		t.Fatal("long password rejected")
	}
	// Passwords sharing a 72-byte prefix must still be distinguished.
	if _, ok := CheckPassword("long-password-user", long[:len(long)-3]+"X"); ok {
		t.Fatal("password differing only after 72 bytes was accepted")
	}
}

func TestLegacyHashIsUpgradedOnLogin(t *testing.T) {
	legacy := models.User{
		UUID:     "legacy-user-uuid",
		Username: "legacy-user",
		Passwd:   legacyHashPasswd("Old-password1"),
	}
	if err := dbcore.GetDBInstance().Create(&legacy).Error; err != nil {
		t.Fatalf("create legacy user: %v", err)
	}
	t.Cleanup(func() { _ = DeleteAccountByUsername("legacy-user") })

	if _, ok := CheckPassword("legacy-user", "wrong-password"); ok {
		t.Fatal("wrong password accepted for legacy hash")
	}
	if stored := storedPasswd(t, "legacy-user"); stored != legacy.Passwd {
		t.Fatal("failed login must not rewrite the stored hash")
	}

	if uuid, ok := CheckPassword("legacy-user", "Old-password1"); !ok || uuid != legacy.UUID {
		t.Fatalf("CheckPassword(legacy) = %q, %v", uuid, ok)
	}
	if stored := storedPasswd(t, "legacy-user"); !isBcryptHash(stored) {
		t.Fatalf("legacy hash was not upgraded, stored %q", stored)
	}
	if _, ok := CheckPassword("legacy-user", "Old-password1"); !ok {
		t.Fatal("password rejected after hash upgrade")
	}
}

func TestUpdateUserAndForceResetUseBcrypt(t *testing.T) {
	user, err := CreateAccount("reset-user", "First-password1")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() { _ = DeleteAccountByUsername("reset-user") })

	second := "Second-password2"
	if err := UpdateUser(user.UUID, nil, &second, nil); err != nil {
		t.Fatalf("update user: %v", err)
	}
	if _, ok := CheckPassword("reset-user", second); !ok {
		t.Fatal("password from UpdateUser rejected")
	}

	if err := ForceResetPassword("reset-user", "Third-password3"); err != nil {
		t.Fatalf("force reset: %v", err)
	}
	if !isBcryptHash(storedPasswd(t, "reset-user")) {
		t.Fatal("ForceResetPassword did not store a bcrypt hash")
	}
	if _, ok := CheckPassword("reset-user", "Third-password3"); !ok {
		t.Fatal("password from ForceResetPassword rejected")
	}
}
