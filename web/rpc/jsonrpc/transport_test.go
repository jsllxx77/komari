package jsonrpc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/pkg/rpc"
	"github.com/komari-monitor/komari/web/api"
)

func performRPCPost(principal *rpc.Principal, body []byte) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/rpc2", func(c *gin.Context) {
		api.SetPrincipal(c, principal)
		c.Next()
	}, OnRpcRequest)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/rpc2", bytes.NewReader(body)))
	return w
}

func TestServePostRejectsOversizedAnonymousBody(t *testing.T) {
	body := bytes.Repeat([]byte(" "), int(maxAnonymousRPCBody)+1)
	w := performRPCPost(rpc.NewAnonymousPrincipal(), body)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestServePostAllowsLargerAuthenticatedBody(t *testing.T) {
	request := []byte(`{"jsonrpc":"2.0","id":1,"method":"rpc.ping"}`)
	body := append(bytes.Repeat([]byte(" "), int(maxAnonymousRPCBody)+1), request...)
	w := performRPCPost(rpc.NewUserPrincipal("user"), body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
}
