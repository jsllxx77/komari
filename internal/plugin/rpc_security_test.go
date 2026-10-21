package plugin

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/pkg/rpc"
)

// TestPluginRPCBareNameDefaultsToAdmin covers the F-14 acceptance criterion:
// a plugin method registered with a bare name (and no public_rpc declaration)
// is callable only by admins at the RPC boundary.
func TestPluginRPCBareNameDefaultsToAdmin(t *testing.T) {
	withTempDataDir(t)
	gin.SetMode(gin.TestMode)
	Init(gin.New())

	zipPath := writePluginZip(t, map[string]string{
		"komari-plugin.json": `{"name":"SecBare","short":"secbare","version":"1.0.0","permissions":{"timeout":5}}`,
		"script.js": `
			const server = require("server");
			function load() {
				server.registerRPC("secBareAdmin", (params) => ({ ok: true }));
				server.registerRPC("plugin:secPrefAdmin", (params) => ({ ok: true }));
			}
		`,
	})
	if _, err := InstallZip(zipPath); err != nil {
		t.Fatal(err)
	}
	if err := SetEnabled("secbare", true, false); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = SetEnabled("secbare", false, false) }()

	for _, method := range []string{"secBareAdmin", "plugin:secPrefAdmin"} {
		if got := rpc.RequiredRole(method); got != rpc.RoleAdmin {
			t.Errorf("RequiredRole(%q) = %q, want %q", method, got, rpc.RoleAdmin)
		}
		if rpc.CheckPrincipal(rpc.NewAnonymousPrincipal(), method) {
			t.Errorf("anonymous visitor must not be allowed to call %q by default", method)
		}
		if !rpc.CheckPrincipal(rpc.NewUserPrincipal("admin-1"), method) {
			t.Errorf("admin must be allowed to call %q", method)
		}
	}

	// The handler itself still works when invoked directly (the ACL gate lives
	// in Dispatch; CallWithContext bypasses it, mirroring internal callers).
	resp := rpc.CallWithContext(context.Background(), nil, "secBareAdmin", map[string]any{"x": 1})
	if resp.Error != nil {
		t.Fatalf("bare handler invocation failed: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok || result["ok"] != true {
		t.Fatalf("unexpected result: %#v", resp.Result)
	}
}

// TestPluginRPCPublicRPCAllowsGuest covers the second acceptance criterion:
// methods explicitly listed in the manifest's public_rpc are callable by
// anonymous visitors.
func TestPluginRPCPublicRPCAllowsGuest(t *testing.T) {
	withTempDataDir(t)
	gin.SetMode(gin.TestMode)
	Init(gin.New())

	zipPath := writePluginZip(t, map[string]string{
		"komari-plugin.json": `{"name":"SecPub","short":"secpub","version":"1.0.0","permissions":{"timeout":5},"public_rpc":["secBarePublic"]}`,
		"script.js": `
			const server = require("server");
			function load() {
				server.registerRPC("secBarePublic", (params) => ({ ok: true, public: true }));
				server.registerRPC("secBarePrivate", (params) => ({ ok: true }));
			}
		`,
	})
	if _, err := InstallZip(zipPath); err != nil {
		t.Fatal(err)
	}
	if err := SetEnabled("secpub", true, false); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = SetEnabled("secpub", false, false) }()

	if got := rpc.RequiredRole("secBarePublic"); got != rpc.RoleGuest {
		t.Fatalf("RequiredRole(secBarePublic) = %q, want %q", got, rpc.RoleGuest)
	}
	if !rpc.CheckPrincipal(rpc.NewAnonymousPrincipal(), "secBarePublic") {
		t.Fatal("anonymous visitor must be allowed to call a public_rpc bare method")
	}

	resp := rpc.CallWithContext(context.Background(), nil, "secBarePublic", nil)
	if resp.Error != nil {
		t.Fatalf("public handler invocation failed: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok || result["public"] != true {
		t.Fatalf("unexpected result: %#v", resp.Result)
	}

	// A method registered by the same plugin but not listed in public_rpc
	// remains admin-only.
	if got := rpc.RequiredRole("secBarePrivate"); got != rpc.RoleAdmin {
		t.Fatalf("RequiredRole(secBarePrivate) = %q, want %q", got, rpc.RoleAdmin)
	}
	if rpc.CheckPrincipal(rpc.NewAnonymousPrincipal(), "secBarePrivate") {
		t.Fatal("anonymous visitor must not be allowed to call a non-public plugin method")
	}
}

// TestPluginRPCRejectsReservedNamespaces covers the third acceptance
// criterion: registering a method under a built-in namespace is rejected.
func TestPluginRPCRejectsReservedNamespaces(t *testing.T) {
	for _, method := range []string{
		"admin:evil", "common:evil", "guest:evil", "rpc:evil", "client:evil", "rpc.ping",
		"plugin:do*Thing", "*",
	} {
		if err := validatePluginMethodName(method); err == nil {
			t.Errorf("validatePluginMethodName(%q) = nil, want an error", method)
		}
	}
	for _, method := range []string{"doThing", "plugin:doThing", "my-plugin:doThing"} {
		if err := validatePluginMethodName(method); err != nil {
			t.Errorf("validatePluginMethodName(%q) = %v, want nil", method, err)
		}
	}

	// End-to-end: a plugin that tries to register an admin: method fails to
	// load instead of silently registering it.
	withTempDataDir(t)
	gin.SetMode(gin.TestMode)
	Init(gin.New())
	zipPath := writePluginZip(t, map[string]string{
		"komari-plugin.json": `{"name":"SecReserved","short":"secreserved","version":"1.0.0","permissions":{"timeout":5}}`,
		"script.js": `
			const server = require("server");
			function load() { server.registerRPC("admin:evil", () => "hijacked"); }
		`,
	})
	if _, err := InstallZip(zipPath); err != nil {
		t.Fatal(err)
	}
	err := SetEnabled("secreserved", true, false)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("plugin registering admin: method must fail loading with a reserved-namespace error, got %v", err)
	}
	if got := rpc.CallWithContext(context.Background(), nil, "admin:evil", nil); got.Error == nil || got.Error.Code != rpc.MethodNotFound {
		t.Fatalf("admin:evil must not have been registered, got %#v", got)
	}
}

// TestPluginRPCContextObject verifies the read-only call context passed to
// handlers as the second argument, including role mapping and immutability.
func TestPluginRPCContextObject(t *testing.T) {
	withTempDataDir(t)
	gin.SetMode(gin.TestMode)
	Init(gin.New())

	zipPath := writePluginZip(t, map[string]string{
		"komari-plugin.json": `{"name":"SecCtx","short":"secctx","version":"1.0.0","permissions":{"timeout":5}}`,
		"script.js": `
			const server = require("server");
			function load() {
				server.registerRPC("plugin:secCtx", (params, ctx) => {
					const before = ctx.role;
					try { ctx.role = "admin"; } catch (e) { /* frozen */ }
					return {
						role: ctx.role,
						before: before,
						userUUID: ctx.userUUID,
						clientUUID: ctx.clientUUID,
						isAPIKey: ctx.isAPIKey,
						frozen: Object.isFrozen(ctx),
						params: params,
					};
				});
			}
		`,
	})
	if _, err := InstallZip(zipPath); err != nil {
		t.Fatal(err)
	}
	if err := SetEnabled("secctx", true, false); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = SetEnabled("secctx", false, false) }()

	call := func(meta *rpc.ContextMeta) map[string]any {
		ctx := context.Background()
		if meta != nil {
			ctx = rpc.NewContextWithMeta(ctx, meta)
		}
		resp := rpc.CallWithContext(ctx, nil, "plugin:secCtx", map[string]any{"x": 1})
		if resp.Error != nil {
			t.Fatalf("handler failed: %v", resp.Error)
		}
		result, ok := resp.Result.(map[string]any)
		if !ok {
			t.Fatalf("unexpected result type: %#v", resp.Result)
		}
		if result["frozen"] != true {
			t.Fatalf("call context must be frozen, got %#v", result)
		}
		params, ok := result["params"].(map[string]any)
		if !ok || fmt.Sprint(params["x"]) != "1" {
			t.Fatalf("params not passed as the first argument: %#v", result["params"])
		}
		return result
	}

	// Admin session.
	admin := call(&rpc.ContextMeta{Principal: rpc.NewUserPrincipal("user-42"), UserUUID: "user-42"})
	if admin["role"] != "admin" || admin["before"] != "admin" {
		t.Errorf("admin role mapping wrong: %#v", admin)
	}
	if admin["userUUID"] != "user-42" || admin["clientUUID"] != "" || admin["isAPIKey"] != false {
		t.Errorf("admin identity fields wrong: %#v", admin)
	}

	// API key caller.
	apiKey := call(&rpc.ContextMeta{Principal: rpc.NewAPIKeyPrincipal()})
	if apiKey["role"] != "admin" || apiKey["isAPIKey"] != true {
		t.Errorf("api key identity wrong: %#v", apiKey)
	}

	// Agent client token.
	agent := call(&rpc.ContextMeta{Principal: rpc.NewAgentPrincipal("client-9"), ClientUUID: "client-9"})
	if agent["role"] != "client" || agent["clientUUID"] != "client-9" || agent["isAPIKey"] != false {
		t.Errorf("agent identity wrong: %#v", agent)
	}

	// Anonymous caller with no metadata defaults to guest (never admin).
	anon := call(nil)
	if anon["role"] != "guest" || anon["before"] != "guest" || anon["isAPIKey"] != false {
		t.Errorf("anonymous identity wrong: %#v", anon)
	}
}
