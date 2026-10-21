package client

import (
	"crypto/subtle"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/clients"
	"github.com/komari-monitor/komari/internal/config"
	"github.com/komari-monitor/komari/utils"
	"github.com/komari-monitor/komari/web/api"
)

func RegisterClient(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	if auth == "" {
		api.RespondError(c, 403, "Invalid AutoDiscovery Key")
		return
	}
	AutoDiscoveryKey, err := config.GetAs[string](config.AutoDiscoveryKeyKey, "")
	if err != nil {
		api.RespondError(c, 500, "Failed to get AutoDiscovery Key: "+err.Error())
		return
	}
	// Constant-time comparison so the key cannot be recovered byte by byte from
	// response timing. Lengths are not secret.
	if AutoDiscoveryKey == "" ||
		len(AutoDiscoveryKey) < 12 ||
		subtle.ConstantTimeCompare([]byte(auth), []byte("Bearer "+AutoDiscoveryKey)) != 1 {

		api.RespondError(c, 403, "Invalid AutoDiscovery Key")
		return
	}
	name := c.Query("name")
	if name == "" {
		name = utils.GenerateRandomString(8)
	}
	name = "Auto-" + name
	uuid, token, err := clients.CreateClientWithName(name)
	if err != nil {
		api.RespondError(c, 500, "Failed to create client: "+err.Error())
		return
	}
	api.RespondSuccess(c, gin.H{"uuid": uuid, "token": token})
}
