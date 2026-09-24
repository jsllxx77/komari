package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func newTokenTestContext(body io.Reader) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/api/anything", body)
	return c
}

func TestExtractClientTokenReadsSmallJSONBody(t *testing.T) {
	payload := `{"token":"agent-token","other":1}`
	c := newTokenTestContext(strings.NewReader(payload))

	if got := extractClientToken(c); got != "agent-token" {
		t.Fatalf("token = %q, want %q", got, "agent-token")
	}
	rest, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(rest) != payload {
		t.Fatalf("restored body = %q, want %q", rest, payload)
	}
}

// countingReader records how many bytes were pulled from the client body.
type countingReader struct {
	r    io.Reader
	read int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	return n, err
}

func TestExtractClientTokenBoundsBufferedBody(t *testing.T) {
	large := bytes.Repeat([]byte("a"), maxTokenBodyPeek*4)
	source := &countingReader{r: bytes.NewReader(large)}
	c := newTokenTestContext(source)

	if got := extractClientToken(c); got != "" {
		t.Fatalf("token = %q, want empty", got)
	}
	if source.read > maxTokenBodyPeek+1 {
		t.Fatalf("middleware consumed %d bytes, want at most %d", source.read, maxTokenBodyPeek+1)
	}
	rest, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if !bytes.Equal(rest, large) {
		t.Fatalf("downstream body length = %d, want %d", len(rest), len(large))
	}
}
