package jsonrpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/pkg/rpc"
	"github.com/komari-monitor/komari/web/api"
)

// dialRPCWebSocket 起一个只挂 /api/rpc2 的测试服务器，并以给定主体建立 WebSocket 连接。
func dialRPCWebSocket(t *testing.T, principal *rpc.Principal) *websocket.Conn {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/rpc2", func(c *gin.Context) {
		api.SetPrincipal(c, principal)
		c.Next()
	}, OnRpcRequest)
	server := httptest.NewServer(r)
	t.Cleanup(server.Close)

	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/rpc2"
	header := http.Header{"Origin": {server.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(url, header)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// sendAndCollect 快速发送 n 条消息，然后读回所有响应，返回被限速的条数与连接是否被服务端关闭。
func sendAndCollect(t *testing.T, conn *websocket.Conn, n int) (limited, answered int, closed bool) {
	t.Helper()
	for i := 0; i < n; i++ {
		msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"rpc.ping"}`, i+1)
		if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			break // 服务端已断开
		}
	}
	for answered < n {
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, data, err := conn.ReadMessage()
		if err != nil {
			// 超时说明连接还开着；其它错误（关闭帧、EOF）说明服务端断开了连接。
			var netErr net.Error
			closed = !(errors.As(err, &netErr) && netErr.Timeout())
			return limited, answered, closed
		}
		answered++
		var resp struct {
			Error *rpc.JsonRpcError `json:"error"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			t.Fatalf("decode %s: %v", data, err)
		}
		if resp.Error != nil && resp.Error.Code == rpc.RateLimited {
			if resp.Error.Message != "rate limited" {
				t.Fatalf("rate-limit message = %q", resp.Error.Message)
			}
			limited++
		}
	}
	return limited, answered, closed
}

func TestAnonymousWebSocketMessagesAreRateLimited(t *testing.T) {
	resetAnonLimiter()
	t.Cleanup(resetAnonLimiter)
	conn := dialRPCWebSocket(t, rpc.NewAnonymousPrincipal())

	limited, answered, closed := sendAndCollect(t, conn, 100)
	if limited == 0 {
		t.Fatalf("100 quick anonymous messages were never rate limited (answered %d)", answered)
	}
	// 突发 30 个令牌，之后连续 20 条被拒就断开：不会把 100 条都处理完。
	if answered >= 100 || !closed {
		t.Fatalf("connection was not closed after repeated rate-limit rejections: answered=%d limited=%d closed=%v", answered, limited, closed)
	}
	if limited > maxConsecutiveRateLimitedWSMessages {
		t.Fatalf("%d rejected messages before closing, want at most %d", limited, maxConsecutiveRateLimitedWSMessages)
	}
}

func TestAuthenticatedWebSocketMessagesAreNotRateLimited(t *testing.T) {
	for name, principal := range map[string]*rpc.Principal{
		"admin": rpc.NewUserPrincipal("ws-admin"),
		"agent": rpc.NewAgentPrincipal("ws-agent"),
	} {
		t.Run(name, func(t *testing.T) {
			resetAnonLimiter()
			t.Cleanup(resetAnonLimiter)
			conn := dialRPCWebSocket(t, principal)
			limited, answered, _ := sendAndCollect(t, conn, 100)
			if limited != 0 || answered != 100 {
				t.Fatalf("%s connection was limited: limited=%d answered=%d", name, limited, answered)
			}
		})
	}
}

func TestRateLimitKeyGroupsIPv6By64(t *testing.T) {
	if rateLimitKey("2001:db8:1:2::1") != rateLimitKey("2001:db8:1:2:ffff:ffff:ffff:ffff") {
		t.Fatal("addresses in the same /64 must share a bucket")
	}
	if rateLimitKey("2001:db8:1:2::1") == rateLimitKey("2001:db8:1:3::1") {
		t.Fatal("different /64 prefixes must not share a bucket")
	}
	if got := rateLimitKey("203.0.113.7"); got != "203.0.113.7" {
		t.Fatalf("IPv4 key = %q", got)
	}
	if got := rateLimitKey("::ffff:203.0.113.7"); got != "203.0.113.7" {
		t.Fatalf("IPv4-mapped key = %q", got)
	}

	// 同一 /64 内换地址不能重新获得突发额度。
	resetAnonLimiter()
	t.Cleanup(resetAnonLimiter)
	for i := 0; i < anonymousRPCBurst; i++ {
		if !anonRateLimiter.allow(fmt.Sprintf("2001:db8:1:2::%x", i+1), 1) {
			t.Fatalf("request %d rejected before the burst was used", i)
		}
	}
	if anonRateLimiter.allow("2001:db8:1:2::ffff", 1) {
		t.Fatal("rotating addresses inside one /64 bypassed the limiter")
	}
}
