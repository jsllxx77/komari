package qq

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizationURLCarriesStateInRedirectURI(t *testing.T) {
	var captured url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.URL.Query()
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "url": "https://example.com/authorize"})
	}))
	defer server.Close()

	provider := &QQ{Addition: Addition{
		AggregationURL: server.URL,
		AppId:          "app",
		AppKey:         "key",
		LoginType:      "qq",
	}}
	if err := provider.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}

	_, state := provider.GetAuthorizationURL("https://panel.example.com/api/oauth_callback")
	if state == "" {
		t.Fatal("empty state")
	}

	redirectURI := captured.Get("redirect_uri")
	if redirectURI == "" {
		t.Fatalf("aggregation request did not carry redirect_uri: %v", captured)
	}
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("parse redirect uri: %v", err)
	}
	if got := parsed.Query().Get("ks"); got != state {
		t.Fatalf("redirect_uri ks = %q, want %q (uri %q)", got, state, redirectURI)
	}
	if !strings.HasSuffix(parsed.Path, "/api/oauth_callback") {
		t.Fatalf("unexpected redirect path: %q", parsed.Path)
	}
}

func TestAuthorizationURLKeepsExistingQuery(t *testing.T) {
	var captured url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.URL.Query()
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "url": "https://example.com/authorize"})
	}))
	defer server.Close()

	provider := &QQ{Addition: Addition{AggregationURL: server.URL, AppId: "a", AppKey: "b", LoginType: "qq"}}
	if err := provider.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	_, state := provider.GetAuthorizationURL("https://panel.example.com/api/oauth_callback?from=oauth")

	parsed, err := url.Parse(captured.Get("redirect_uri"))
	if err != nil {
		t.Fatalf("parse redirect uri: %v", err)
	}
	query := parsed.Query()
	if query.Get("from") != "oauth" || query.Get("ks") != state {
		t.Fatalf("redirect uri lost parameters: %q", parsed.String())
	}
}
