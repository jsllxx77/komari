package rpc

import "testing"

// TestNormalizeMethodName verifies that bare plugin method names are mapped to
// the same canonical name the permission resolver uses, while namespaced and
// internal names are left untouched.
func TestNormalizeMethodName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"doThing", "common:doThing"},
		{"getNodes", "common:getNodes"},
		{"common:doThing", "common:doThing"},
		{"plugin:doThing", "plugin:doThing"},
		{"admin:addClient", "admin:addClient"},
		{"rpc.ping", "rpc.ping"},
	}
	for _, c := range cases {
		if got := NormalizeMethodName(c.in); got != c.want {
			t.Errorf("NormalizeMethodName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAllowNormalizedBareMethod locks in the security fix: a rule declared for
// a bare method must actually win over the permissive "common:*" fallback.
func TestAllowNormalizedBareMethod(t *testing.T) {
	const adminOnly = "bareAclAdminOnly"
	Allow(NormalizeMethodName(adminOnly), RoleAdmin)
	if got := RequiredRole(adminOnly); got != RoleAdmin {
		t.Fatalf("RequiredRole(%q) = %q, want %q", adminOnly, got, RoleAdmin)
	}
	if CheckPrincipal(NewAnonymousPrincipal(), adminOnly) {
		t.Fatalf("anonymous principal must not be allowed to call admin-only bare method %q", adminOnly)
	}
	if !CheckPrincipal(NewUserPrincipal("admin-user"), adminOnly) {
		t.Fatalf("admin principal must be allowed to call %q", adminOnly)
	}

	const guestAllowed = "bareAclGuestAllowed"
	Allow(NormalizeMethodName(guestAllowed), RoleGuest)
	if got := RequiredRole(guestAllowed); got != RoleGuest {
		t.Fatalf("RequiredRole(%q) = %q, want %q", guestAllowed, got, RoleGuest)
	}
	if !CheckPrincipal(NewAnonymousPrincipal(), guestAllowed) {
		t.Fatalf("anonymous principal must be allowed to call public bare method %q", guestAllowed)
	}
}

// TestNormalizeMethodNameMatchesResolver ensures NormalizeMethodName stays in
// sync with resolveMinRole for the names a plugin can register.
func TestNormalizeMethodNameMatchesResolver(t *testing.T) {
	for _, method := range []string{"doThing", "plugin:doThing", "my-plugin.doThing"} {
		normalized := NormalizeMethodName(method)
		if got := RequiredRole(method); got != RequiredRole(normalized) {
			t.Errorf("RequiredRole(%q) = %q but RequiredRole(%q) = %q; normalization is out of sync",
				method, got, normalized, RequiredRole(normalized))
		}
	}
}
