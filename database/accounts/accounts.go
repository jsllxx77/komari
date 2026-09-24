package accounts

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	logger "github.com/komari-monitor/komari/utils/log"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// 密码以 bcrypt(base64(SHA-256(password))) 存储。SHA-256 预哈希让任意长度的
// 密码都落在 bcrypt 的 72 字节输入上限内（安装向导允许最长 256 个字符）。
//
// 旧版本使用全局固定盐的单次 SHA-256，仍可用于校验，并在下一次登录成功时
// 自动升级为 bcrypt。
const legacyPasswordSalt = "06Wm4Jv1Hkxx"

// CheckPassword 检查密码是否正确
//
// 如果密码正确，返回用户的 UUID 和 true；否则返回空字符串和 false
func CheckPassword(username, passwd string) (uuid string, success bool) {
	db := dbcore.GetDBInstance()
	var user models.User
	result := db.Where("username = ?", username).First(&user)
	if result.Error != nil {
		// 用户不存在时同样执行一次 bcrypt 比较，避免通过响应耗时探测用户名。
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash(), prehashPasswd(passwd))
		return "", false
	}
	ok, needsUpgrade := verifyPasswd(user.Passwd, passwd)
	if !ok {
		return "", false
	}
	if needsUpgrade {
		upgradePasswordHash(db, user, passwd)
	}
	return user.UUID, true
}

// upgradePasswordHash 将校验通过的旧哈希替换为当前格式。仅在库中仍是刚校验
// 过的哈希时才更新，避免覆盖并发发生的密码修改。失败不影响本次登录。
func upgradePasswordHash(db *gorm.DB, user models.User, passwd string) {
	hashed, err := hashPasswd(passwd)
	if err != nil {
		logger.Warnf("accounts", "failed to upgrade password hash for user %s: %v", user.UUID, err)
		return
	}
	err = db.Model(&models.User{}).
		Where("uuid = ? AND passwd = ?", user.UUID, user.Passwd).
		Update("passwd", hashed).Error
	if err != nil {
		logger.Warnf("accounts", "failed to upgrade password hash for user %s: %v", user.UUID, err)
	}
}

// ForceResetPassword 强制重置用户密码
func ForceResetPassword(username, passwd string) (err error) {
	hashed, err := hashPasswd(passwd)
	if err != nil {
		return err
	}
	db := dbcore.GetDBInstance()
	result := db.Model(&models.User{}).Where("username = ?", username).Update("passwd", hashed)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("无法找到用户名")
	}
	return nil
}

// hashPasswd 使用 bcrypt 生成密码哈希
func hashPasswd(passwd string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword(prehashPasswd(passwd), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hashed), nil
}

// verifyPasswd 校验密码，并报告存储的哈希是否需要升级为当前格式。
func verifyPasswd(stored, passwd string) (ok bool, needsUpgrade bool) {
	if isBcryptHash(stored) {
		if bcrypt.CompareHashAndPassword([]byte(stored), prehashPasswd(passwd)) != nil {
			return false, false
		}
		cost, err := bcrypt.Cost([]byte(stored))
		return true, err != nil || cost < bcrypt.DefaultCost
	}
	if subtle.ConstantTimeCompare([]byte(legacyHashPasswd(passwd)), []byte(stored)) != 1 {
		return false, false
	}
	return true, true
}

func isBcryptHash(stored string) bool {
	return strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$")
}

func prehashPasswd(passwd string) []byte {
	sum := sha256.Sum256([]byte(passwd))
	return []byte(base64.StdEncoding.EncodeToString(sum[:]))
}

// legacyHashPasswd 复现旧版本的密码哈希，仅用于校验尚未升级的账户。
func legacyHashPasswd(passwd string) string {
	sum := sha256.Sum256([]byte(passwd + legacyPasswordSalt))
	return base64.StdEncoding.EncodeToString(sum[:])
}

var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

// dummyPasswordHash 返回一个随机密码的 bcrypt 哈希，用于让不存在的用户名也消耗同等的校验时间。
func dummyPasswordHash() []byte {
	dummyHashOnce.Do(func() {
		random := make([]byte, 32)
		_, _ = rand.Read(random)
		dummyHash, _ = bcrypt.GenerateFromPassword(prehashPasswd(string(random)), bcrypt.DefaultCost)
	})
	return dummyHash
}

func CreateAccount(username, passwd string) (user models.User, err error) {
	return CreateAccountWithDB(dbcore.GetDBInstance(), username, passwd)
}

func CreateAccountWithDB(db *gorm.DB, username, passwd string) (user models.User, err error) {
	hashedPassword, err := hashPasswd(passwd)
	if err != nil {
		return models.User{}, err
	}
	user = models.User{
		UUID:     uuid.New().String(),
		Username: username,
		Passwd:   hashedPassword,
	}
	err = db.Create(&user).Error
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

func DeleteAccountByUsername(username string) (err error) {
	return DeleteAccountByUsernameWithDB(dbcore.GetDBInstance(), username)
}

func DeleteAccountByUsernameWithDB(db *gorm.DB, username string) (err error) {
	err = db.Where("username = ?", username).Delete(&models.User{}).Error
	if err != nil {
		return err
	}
	return nil
}

func GetUserByUUID(uuid string) (user models.User, err error) {
	db := dbcore.GetDBInstance()
	err = db.Where("uuid = ?", uuid).First(&user).Error
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

// 通过 SSO 信息获取用户
func GetUserBySSO(ssoID string) (user models.User, err error) {
	db := dbcore.GetDBInstance()

	// 首先尝试查找已存在的用户
	err = db.Where("sso_id = ?", ssoID).First(&user).Error
	if err == nil {
		return user, nil
	}

	// 如果找不到用户，返回明确的错误信息
	return models.User{}, fmt.Errorf("用户不存在：%s", ssoID)
}

func BindingExternalAccount(uuid string, sso_id string) error {
	db := dbcore.GetDBInstance()
	err := db.Model(&models.User{}).Where("uuid = ?", uuid).Update("sso_id", sso_id).Error
	if err != nil {
		return err
	}
	return nil
}

func UnbindExternalAccount(uuid string) error {
	db := dbcore.GetDBInstance()
	err := db.Model(&models.User{}).Where("uuid = ?", uuid).Update("sso_id", "").Error
	if err != nil {
		return err
	}
	return nil
}

func UpdateUser(uuid string, name, password, sso_type *string) error {
	db := dbcore.GetDBInstance()
	// Check if user exists
	var existingUser models.User
	result := db.Where("uuid = ?", uuid).First(&existingUser)
	if result.Error != nil {
		return fmt.Errorf("user not found: %s", uuid)
	}
	updates := make(map[string]interface{})
	if name != nil {
		updates["username"] = *name
	}
	if password != nil {
		hashed, err := hashPasswd(*password)
		if err != nil {
			return err
		}
		updates["passwd"] = hashed
	}
	if sso_type != nil {
		updates["sso_type"] = *sso_type
	}
	updates["updated_at"] = time.Now().UTC()
	err := db.Model(&models.User{}).Where("uuid = ?", uuid).Updates(updates).Error
	if err != nil {
		return err
	}
	if password != nil {
		DeleteAllSessions()
	}
	return nil
}
