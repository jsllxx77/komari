package accounts

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	messageevent "github.com/komari-monitor/komari/database/models/messageEvent"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/utils"
	"github.com/komari-monitor/komari/utils/geoip"
	"github.com/komari-monitor/komari/utils/messageSender"
)

// GetAllSessions 获取所有会话
func GetAllSessions() (sessions []models.Session, err error) {
	db := dbcore.GetDBInstance()
	err = db.Find(&sessions).Error
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// CreateSession 创建新会话
func CreateSession(uuid string, expires int, userAgent, ip, login_method string) (string, error) {
	db := dbcore.GetDBInstance()
	session := utils.GenerateRandomString(32)

	sessionRecord := models.Session{
		UUID:         uuid,
		Session:      session,
		Expires:      time.Now().UTC().Add(time.Duration(expires) * time.Second),
		UserAgent:    userAgent,
		Ip:           ip,
		LoginMethod:  login_method,
		LatestOnline: time.Now().UTC(),
	}
	go func() {
		LoginNotification, _ := config.GetAs[bool](config.LoginNotificationKey, false)
		if LoginNotification {
			ipAddr := net.ParseIP(ip)
			ipinfo, _ := geoip.GetGeoInfo(ipAddr)
			loc := "unknown"
			if ipinfo != nil && ipinfo.Name != "" {
				loc = ipinfo.Name
			}
			_ = messageSender.SendNotification(models.EventMessage{
				Event:   messageevent.Login,
				Time:    time.Now().UTC(),
				Message: fmt.Sprintf("%s: %s (%s)\n%s", login_method, ip, loc, userAgent),
				Emoji:   "🔑",
			})
		}
	}()

	err := db.Create(&sessionRecord).Error
	if err != nil {
		return "", err
	}
	return session, nil
}

// GetSession 根据会话 ID 获取 UUID
func GetSession(session string) (uuid string, err error) {
	db := dbcore.GetDBInstance()
	var sessionRecord models.Session
	err = db.Where("session = ?", session).First(&sessionRecord).Error
	if err != nil {
		return "", err
	}

	if time.Now().UTC().After(sessionRecord.Expires) {
		// 会话已过期，删除它
		_ = DeleteSession(session)
		return "", errors.New("session expired")
	}

	return sessionRecord.UUID, nil
}

// GetUserBySession 根据会话 ID 获取用户。会话有效性（存在且未过期）由
// GetSession 负责检查，过期会话会被删除，因此这里不会返回已过期的登录态。
func GetUserBySession(session string) (models.User, error) {
	uuid, err := GetSession(session)
	if err != nil {
		return models.User{}, err
	}
	return GetUserByUUID(uuid)
}

// DeleteSession 删除指定会话
func DeleteSession(session string) (err error) {
	db := dbcore.GetDBInstance()
	result := db.Where("session = ?", session).Delete(&models.Session{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func DeleteAllSessions() error {
	db := dbcore.GetDBInstance()
	result := db.Where("1 = 1").Delete(&models.Session{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// DeleteSessionsExcept 删除指定用户除 keep 之外的所有会话。
// 用于启用 2FA、修改密码等场景撤销可能已被他人持有的旧会话。
func DeleteSessionsExcept(uuid, keep string) error {
	if uuid == "" {
		return errors.New("uuid is required")
	}
	db := dbcore.GetDBInstance()
	query := db.Where("uuid = ?", uuid)
	if keep != "" {
		query = query.Where("session <> ?", keep)
	}
	return query.Delete(&models.Session{}).Error
}

// MarkSessionMFAVerified 记录该会话最近一次通过 TOTP 校验的时间。
// 敏感操作的 step-up 窗口以此为准，避免每个操作都要求重新输入验证码。
func MarkSessionMFAVerified(session string) error {
	if session == "" {
		return errors.New("session is required")
	}
	db := dbcore.GetDBInstance()
	now := time.Now().UTC()
	return db.Model(&models.Session{}).
		Where("session = ?", session).
		Update("mfa_verified_at", now).Error
}

// SessionMFAVerifiedAt 返回该会话最近一次通过 TOTP 校验的时间。
func SessionMFAVerifiedAt(session string) (time.Time, bool, error) {
	if session == "" {
		return time.Time{}, false, errors.New("session is required")
	}
	db := dbcore.GetDBInstance()
	var record models.Session
	if err := db.Select("mfa_verified_at").Where("session = ?", session).First(&record).Error; err != nil {
		return time.Time{}, false, err
	}
	if record.MfaVerifiedAt == nil || record.MfaVerifiedAt.IsZero() {
		return time.Time{}, false, nil
	}
	return record.MfaVerifiedAt.UTC(), true, nil
}

func UpdateLatest(session, useragent, ip string) error {
	db := dbcore.GetDBInstance()
	return db.Model(&models.Session{}).Where("session = ?", session).Updates(map[string]interface{}{
		"latest_online":     time.Now().UTC(),
		"latest_user_agent": useragent,
		"latest_ip":         ip,
	}).Error
}

func RemoveExpiredSessions() error {
	db := dbcore.GetDBInstance()
	result := db.Where("expires < ?", time.Now().UTC()).Delete(&models.Session{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}
