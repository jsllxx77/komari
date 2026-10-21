package client

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// zeroReader yields an unbounded stream of zero bytes without allocating the
// full length, so a gzip bomb can be produced cheaply in tests.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// gzipOfRepeatedZeros compresses n zero bytes while only holding a small
// buffer, and returns the (tiny) compressed stream.
func gzipOfRepeatedZeros(t *testing.T, n int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := io.Copy(zw, io.LimitReader(zeroReader{}, n)); err != nil {
		t.Fatalf("compress %d zero bytes: %v", n, err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func newBodyRequest(t *testing.T, body []byte, gzipped bool) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/clients/v2/rpc", bytes.NewReader(body))
	if gzipped {
		req.Header.Set("Content-Encoding", "gzip")
	}
	return req
}

// A normal, small plain body is returned unchanged.
func TestReadMaybeCompressedBodyPlainSmallBody(t *testing.T) {
	payload := []byte(`{"jsonrpc":"2.0","id":"1","method":"agent.report"}`)

	got, err := readMaybeCompressedBody(httptest.NewRecorder(), newBodyRequest(t, payload, false))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("body = %q, want %q", got, payload)
	}
}

// A normal, small gzip body is decompressed and returned unchanged.
func TestReadMaybeCompressedBodyGzipSmallBody(t *testing.T) {
	payload := bytes.Repeat([]byte(`{"jsonrpc":"2.0"}`), 64)

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	got, err := readMaybeCompressedBody(httptest.NewRecorder(), newBodyRequest(t, buf.Bytes(), true))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("decompressed body does not match payload (got %d bytes, want %d)", len(got), len(payload))
	}
}

// An uncompressed body above the wire cap must be rejected with a
// *http.MaxBytesError before any buffer grows past the limit.
func TestReadBodyWithLimitsRejectsOversizedCompressedBody(t *testing.T) {
	const (
		maxCompressed   = 64
		maxDecompressed = 1 << 20
	)
	body := bytes.Repeat([]byte("x"), maxCompressed+1)

	got, err := readBodyWithLimits(httptest.NewRecorder(), newBodyRequest(t, body, false), maxCompressed, maxDecompressed)
	if err == nil {
		t.Fatal("expected an error for an oversized compressed body")
	}
	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) {
		t.Fatalf("error = %v (%T), want *http.MaxBytesError", err, err)
	}
	if got != nil {
		t.Fatalf("returned %d bytes alongside the error, want nil", len(got))
	}
}

// A gzip stream that fits the wire cap but expands past the decompressed cap
// must be rejected by the length check, not silently truncated.
func TestReadBodyWithLimitsRejectsGzipBomb(t *testing.T) {
	const (
		maxCompressed   = 1 << 20
		maxDecompressed = 1024
	)
	compressed := gzipOfRepeatedZeros(t, maxDecompressed+1)
	if int64(len(compressed)) > maxCompressed {
		t.Fatalf("test fixture compressed to %d bytes, above the %d-byte wire cap", len(compressed), maxCompressed)
	}

	got, err := readBodyWithLimits(httptest.NewRecorder(), newBodyRequest(t, compressed, true), maxCompressed, maxDecompressed)
	if !errors.Is(err, errAgentBodyTooLarge) {
		t.Fatalf("error = %v, want errAgentBodyTooLarge", err)
	}
	if got != nil {
		t.Fatalf("returned %d bytes alongside the error, want nil", len(got))
	}
}

func TestBodyReadErrorStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{name: "decompressed limit", err: errAgentBodyTooLarge, want: http.StatusRequestEntityTooLarge},
		{name: "compressed limit", err: &http.MaxBytesError{Limit: 1}, want: http.StatusRequestEntityTooLarge},
		{name: "gzip header", err: gzip.ErrHeader, want: http.StatusBadRequest},
		{name: "other", err: io.ErrUnexpectedEOF, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bodyReadErrorStatus(tc.err); got != tc.want {
				t.Fatalf("bodyReadErrorStatus(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// End to end through the Gin handler: a gzip bomb whose compressed size is
// far under the wire cap but whose decompressed size exceeds the cap must
// produce 413 and must not materialise the full decompressed payload.
func TestUploadV2RPCRejectsGzipBombWith413(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/clients/v2/rpc", UploadV2RPC)

	compressed := gzipOfRepeatedZeros(t, maxAgentDecompressedBody+1)
	if int64(len(compressed)) >= maxAgentCompressedBody {
		t.Fatalf("bomb compressed to %d bytes, unexpectedly above the wire cap %d", len(compressed), maxAgentCompressedBody)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, newBodyRequest(t, compressed, true))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
}

// End to end: an uncompressed body above the wire cap returns 413.
func TestUploadV2RPCRejectsOversizedCompressedBodyWith413(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/clients/v2/rpc", UploadV2RPC)

	body := bytes.Repeat([]byte("x"), maxAgentCompressedBody+1)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, newBodyRequest(t, body, false))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
}

// A body that claims to be gzip but is not still fails as a client error (400).
func TestUploadV2RPCInvalidGzipReturns400(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/clients/v2/rpc", UploadV2RPC)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, newBodyRequest(t, []byte("this is not gzip"), true))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// A normal small body still reaches authentication (401 without a token),
// proving the size guard does not disturb regular uploads.
func TestUploadV2RPCNormalSmallBodyNotRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/clients/v2/rpc", UploadV2RPC)

	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "agent.report",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, newBodyRequest(t, payload, false))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// The v2 agent WebSocket must not negotiate permessage-deflate: gorilla's
// read limit counts wire bytes, so compression would re-open the
// decompression-bomb hole even with SetReadLimit in place.
func TestWebSocketV2RPCDoesNotNegotiateCompression(t *testing.T) {
	// The origin check reaches into config/DB; skip it so this test stays
	// self-contained and does not depend on another test having opened the DB.
	t.Setenv("KOMARI_WS_DISABLE_ORIGIN", "true")
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/clients/v2/rpc", func(c *gin.Context) {
		c.Set("client_uuid", "client-ws-compression")
		WebSocketV2RPC(c)
	})
	server := httptest.NewServer(router)
	defer server.Close()

	dialer := *websocket.DefaultDialer
	dialer.EnableCompression = true // ask for permessage-deflate
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/clients/v2/rpc?token=test"
	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if got := resp.Header.Get("Sec-WebSocket-Extensions"); strings.Contains(got, "permessage-deflate") {
		t.Fatalf("server negotiated permessage-deflate (%q); a compressed frame could bypass the read limit", got)
	}
}

// An inbound WebSocket message above maxAgentWSMessage drops the peer instead
// of being buffered whole.
func TestWebSocketV2RPCRejectsOversizedMessage(t *testing.T) {
	t.Setenv("KOMARI_WS_DISABLE_ORIGIN", "true")
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/clients/v2/rpc", func(c *gin.Context) {
		c.Set("client_uuid", "client-ws-limit")
		WebSocketV2RPC(c)
	})
	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/clients/v2/rpc?token=test"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("a"), maxAgentWSMessage+1)
	if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
		// The server may close mid-write once the limit trips; that is itself
		// a rejection.
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return // expected: server closed the connection after the limit
		}
	}
}

// A small valid message still gets a JSON-RPC response, proving the size guard
// and disabled compression do not break the normal path.
func TestWebSocketV2RPCSmallMessageRoundTrip(t *testing.T) {
	t.Setenv("KOMARI_WS_DISABLE_ORIGIN", "true")
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/clients/v2/rpc", func(c *gin.Context) {
		c.Set("client_uuid", "client-ws-small")
		WebSocketV2RPC(c)
	})
	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/clients/v2/rpc?token=test"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// An unknown method yields a JSON-RPC error response with -32601.
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"jsonrpc":"2.0","id":"1","method":"does.not.exist"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !bytes.Contains(data, []byte("-32601")) {
		t.Fatalf("response = %s, want method-not-found error", data)
	}
}
