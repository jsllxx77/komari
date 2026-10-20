package public

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestOAuthStateIsSingleUse(t *testing.T) {
	rememberOAuthState("state-1", oauthStateRecord{Kind: oauthIntentBind, UserUUID: "user-1"})

	record, ok := takeOAuthState("state-1")
	if !ok {
		t.Fatal("state record was not found")
	}
	if record.Kind != oauthIntentBind || record.UserUUID != "user-1" {
		t.Fatalf("unexpected record: %#v", record)
	}

	if _, ok := takeOAuthState("state-1"); ok {
		t.Fatal("state record was reusable")
	}
	if _, ok := takeOAuthState(""); ok {
		t.Fatal("an empty state must never match")
	}
	if _, ok := takeOAuthState("never-issued"); ok {
		t.Fatal("an unknown state must not match")
	}
}

func TestOAuthCallbackStateUsesKSForQQ(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/oauth_callback?ks=ksvalue&state=statevalue&code=x", nil)

	if got := oauthCallbackState(c, "qq"); got != "ksvalue" {
		t.Fatalf("qq callback state = %q, want ksvalue", got)
	}
	if got := oauthCallbackState(c, "github"); got != "statevalue" {
		t.Fatalf("github callback state = %q, want statevalue", got)
	}
}
