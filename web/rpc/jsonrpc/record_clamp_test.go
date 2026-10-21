package jsonrpc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/pkg/rpc"
	"github.com/komari-monitor/komari/web/api"
)

func resetAnonLimiter() {
	anonRateLimiter = &anonymousRateLimiter{
		buckets:  make(map[string]*tokenBucket),
		overflow: &tokenBucket{tokens: anonymousRPCBurst, last: time.Now()},
		maxIPs:   10000,
	}
}

func TestRPCLimitsByPrincipal(t *testing.T) {
	if got := rpcBatchLimit(nil); got != maxAnonymousRPCBatch {
		t.Fatalf("nil meta batch limit = %d, want %d", got, maxAnonymousRPCBatch)
	}
	if got := rpcBatchLimit(&rpc.ContextMeta{Principal: rpc.NewAnonymousPrincipal()}); got != maxAnonymousRPCBatch {
		t.Fatalf("anonymous batch limit = %d, want %d", got, maxAnonymousRPCBatch)
	}
	if got := rpcBatchLimit(&rpc.ContextMeta{Principal: rpc.NewUserPrincipal("u")}); got != maxAuthenticatedRPCBatch {
		t.Fatalf("authenticated batch limit = %d, want %d", got, maxAuthenticatedRPCBatch)
	}
	if got := rpcBodyLimit(&rpc.ContextMeta{Principal: rpc.NewAnonymousPrincipal()}); got != maxAnonymousRPCBody {
		t.Fatalf("anonymous body limit = %d, want %d", got, maxAnonymousRPCBody)
	}
}

func buildBatch(n int) []byte {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"jsonrpc":"2.0","id":%d,"method":"public:getVersion"}`, i+1)
	}
	b.WriteString("]")
	return []byte(b.String())
}

func TestServePostRejectsOversizedAnonymousBatch(t *testing.T) {
	resetAnonLimiter()
	w := performRPCPost(rpc.NewAnonymousPrincipal(), buildBatch(maxAnonymousRPCBatch+1))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "batch too large") {
		t.Fatalf("expected batch-too-large error, got %s", w.Body.String())
	}
}

func TestServePostAllowsLargerAuthenticatedBatch(t *testing.T) {
	resetAnonLimiter()
	w := performRPCPost(rpc.NewUserPrincipal("user"), buildBatch(maxAnonymousRPCBatch+1))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestClampRecordMaxCount(t *testing.T) {
	cases := []struct {
		requested int
		isAdmin   bool
		want      int
	}{
		{0, false, defaultRecordMaxCount},
		{-1, false, defaultRecordMaxCount},
		{-5, true, -1},
		{500, false, 500},
		{50000, false, maxRecordMaxCount},
		{50000, true, maxRecordMaxCount},
	}
	for _, tc := range cases {
		if got := clampRecordMaxCount(tc.requested, tc.isAdmin); got != tc.want {
			t.Errorf("clampRecordMaxCount(%d, %v) = %d, want %d", tc.requested, tc.isAdmin, got, tc.want)
		}
	}
}

func TestRecordWindowLimitHoursWithinBounds(t *testing.T) {
	got := recordWindowLimitHours(context.Background())
	if got <= 0 || got > maxRecordWindowHoursLimit {
		t.Fatalf("recordWindowLimitHours = %d, want (0, %d]", got, maxRecordWindowHoursLimit)
	}
}

func TestAnonymousRateLimitMiddleware(t *testing.T) {
	resetAnonLimiter()
	gin.SetMode(gin.TestMode)
	build := func(p *rpc.Principal) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			api.SetPrincipal(c, p)
			c.Next()
		}, AnonymousRateLimit())
		r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
		return r
	}

	anon := build(rpc.NewAnonymousPrincipal())
	got429 := false
	for i := 0; i < anonymousRPCBurst+5; i++ {
		w := httptest.NewRecorder()
		anon.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatalf("anonymous requests were never rate limited")
	}

	auth := build(rpc.NewUserPrincipal("u"))
	for i := 0; i < anonymousRPCBurst+5; i++ {
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("authenticated request %d got %d, want 200", i, w.Code)
		}
	}
}

func TestServePostAnonymousBatchChargesRateLimitTokens(t *testing.T) {
	resetAnonLimiter()
	// 每个批量请求扣 1（中间件之外由 servePost 扣 len-1）：3 次 20 条的批量≈57 个令牌，
	// 超过突发 30，因此其中一次必须被 429 拒绝。
	sawRateLimited := false
	for i := 0; i < 3; i++ {
		w := performRPCPost(rpc.NewAnonymousPrincipal(), buildBatch(maxAnonymousRPCBatch))
		if w.Code == http.StatusTooManyRequests {
			sawRateLimited = true
			break
		}
	}
	if !sawRateLimited {
		t.Fatal("repeated anonymous batches were never rate limited")
	}
}
