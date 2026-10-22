package accounts

import (
	"image"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/pquerna/otp/totp"
)

var (
	TwoFactorIssuer = "Komari Monitor"
)

func Generate2Fa() (string, image.Image, error) {
	otp, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TwoFactorIssuer,
		AccountName: "komari",
	})
	if err != nil {
		return "", nil, err
	}
	img, err := otp.Image(250, 250)
	if err != nil {
		return "", nil, err
	}
	return otp.Secret(), img, nil
}

func Enable2Fa(uuid, secret string) error {
	db := dbcore.GetDBInstance()
	if err := db.Model(&models.User{}).Where("uuid = ?", uuid).Update("two_factor", secret).Error; err != nil {
		return err
	}
	Forget2FAState(uuid)
	return nil
}

// Enable2FaIfDisabled 只在用户尚未启用 2FA 时写入密钥，避免覆盖已有密钥。
// 返回 ErrTwoFactorAlreadyEnabled 表示该账号已经启用了 2FA。
// usedStep 是启用时校验通过的时间窗（Validate2FACodeForSecret 的返回值），
// 大于 0 时会被记为已使用，同一个验证码不能在启用后马上再用一次。
func Enable2FaIfDisabled(uuid, secret string, usedStep int64) error {
	db := dbcore.GetDBInstance()
	result := db.Model(&models.User{}).
		Where("uuid = ? AND (two_factor IS NULL OR two_factor = '')", uuid).
		Update("two_factor", secret)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrTwoFactorAlreadyEnabled
	}
	forget2FAStateWithUsedStep(uuid, usedStep)
	return nil
}

// Verify2Fa 是历史入口，内部已改为走带限速与防重放的 Verify2FaStrict。
// 新代码请直接调用 Verify2FaStrict 以区分锁定与重放错误。
func Verify2Fa(uuid, code string) (bool, error) {
	return Verify2FaStrict(uuid, code)
}

func Disable2Fa(uuid string) error {
	db := dbcore.GetDBInstance()
	if err := db.Model(&models.User{}).Where("uuid = ?", uuid).Update("two_factor", "").Error; err != nil {
		return err
	}
	Forget2FAState(uuid)
	return nil
}
