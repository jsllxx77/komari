package github

import (
	"testing"
)

func TestAuthorizationStateExpiresAndIsSingleUse(t *testing.T) {
	g := &Github{}
	if err := g.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	_, state := g.GetAuthorizationURL("")

	items := g.stateCache.Items()
	item, ok := items[state]
	if !ok {
		t.Fatal("state was not stored")
	}
	if item.Expiration == 0 {
		t.Fatal("state must expire instead of being kept forever")
	}

	// The first callback consumes the state even though it fails later for
	// lacking a code; replaying the same state must then be rejected.
	if _, err := g.OnCallback(nil, state, map[string]string{}, ""); err == nil || err.Error() != "no code provided" {
		t.Fatalf("first callback error = %v, want %q", err, "no code provided")
	}
	if _, err := g.OnCallback(nil, state, map[string]string{"code": "x"}, ""); err == nil || err.Error() != "invalid state" {
		t.Fatalf("replayed callback error = %v, want %q", err, "invalid state")
	}
}
