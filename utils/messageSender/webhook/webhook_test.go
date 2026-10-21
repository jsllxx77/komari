package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const multilineMessage = "node & admin=1 # injected\nsecond line\r\nthird"

func TestReplaceTemplateURLEscapesUntrustedValues(t *testing.T) {
	title := "Title & x=1 #frag\nline"
	raw := "https://hooks.example/notify?message={{message}}&title={{title}}&channel=ops"

	got := replaceTemplateURL(raw, multilineMessage, title)

	if strings.ContainsAny(got, " \n\r#") {
		t.Fatalf("replaceTemplateURL() = %q, want no raw space, line break, or fragment marker", got)
	}

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", got, err)
	}
	query := parsed.Query()
	if value := query.Get("message"); value != multilineMessage {
		t.Fatalf("message parameter = %q, want %q", value, multilineMessage)
	}
	if value := query.Get("title"); value != title {
		t.Fatalf("title parameter = %q, want %q", value, title)
	}
	if value := query.Get("channel"); value != "ops" {
		t.Fatalf("channel parameter = %q, want %q", value, "ops")
	}
	if parsed.Fragment != "" {
		t.Fatalf("fragment = %q, want empty", parsed.Fragment)
	}
	if values, ok := query["admin"]; ok {
		t.Fatalf("message content injected an extra query parameter: admin=%v", values)
	}
}

func TestReplaceTemplateURLKeepsPlainValuesReadable(t *testing.T) {
	got := replaceTemplateURL("https://hooks.example/notify?message={{message}}", "Server-01 offline", "")
	if got != "https://hooks.example/notify?message=Server-01+offline" {
		t.Fatalf("replaceTemplateURL() = %q", got)
	}
}

func TestCreateGETRequestSurvivesMultilineMessage(t *testing.T) {
	sender := &WebhookSender{}
	addition := Addition{
		URL:    "https://hooks.example/notify?message={{message}}&title={{title}}",
		Method: http.MethodGet,
	}

	request, err := sender.createGETRequest(addition, multilineMessage, "Title #1")
	if err != nil {
		t.Fatalf("createGETRequest() error = %v", err)
	}
	query := request.URL.Query()
	if value := query.Get("message"); value != multilineMessage {
		t.Fatalf("message parameter = %q, want %q", value, multilineMessage)
	}
	if value := query.Get("title"); value != "Title #1" {
		t.Fatalf("title parameter = %q, want %q", value, "Title #1")
	}
}

func TestCreatePOSTRequestKeepsRawSubstitution(t *testing.T) {
	sender := &WebhookSender{}
	addition := Addition{
		URL:         "https://hooks.example/notify",
		Method:      http.MethodPost,
		ContentType: "text/plain",
		Body:        "message={{message}} title={{title}}",
	}

	message := "node & admin=1 # injected\nsecond line"
	request, err := sender.createPOSTRequest(addition, message, "Title")
	if err != nil {
		t.Fatalf("createPOSTRequest() error = %v", err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("read POST body: %v", err)
	}
	if want := "message=" + message + " title=Title"; string(body) != want {
		t.Fatalf("POST body = %q, want %q (POST must not be query-escaped)", string(body), want)
	}
}

func TestCreatePOSTRequestKeepsJSONEscaping(t *testing.T) {
	sender := &WebhookSender{}
	addition := Addition{
		URL:         "https://hooks.example/notify",
		Method:      http.MethodPost,
		ContentType: "application/json",
		Body:        `{"message":"{{message}}","title":"{{title}}"}`,
	}

	request, err := sender.createPOSTRequest(addition, "line1\nline2", "Title")
	if err != nil {
		t.Fatalf("createPOSTRequest() error = %v", err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("read POST body: %v", err)
	}
	if !json.Valid(body) {
		t.Fatalf("POST body is not valid JSON: %q", string(body))
	}
	if strings.Contains(string(body), "\n") {
		t.Fatalf("POST body contains a raw newline: %q", string(body))
	}
}
