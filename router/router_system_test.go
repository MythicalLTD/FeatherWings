package router

import (
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/server"
)

func TestPostUpdateConfigurationRotatesCredentials(t *testing.T) {
	t.Setenv("WINGS_TOKEN_ID", "")
	t.Setenv("WINGS_TOKEN", "")

	cfg, err := config.NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthenticationTokenId = "old-id"
	cfg.AuthenticationToken = "old-token"
	if err := cfg.ResolveToken(false); err != nil {
		t.Fatal(err)
	}
	config.Set(cfg)

	credentials := make(chan [2]string, 1)
	manager := server.NewEmptyManager(backupTestRemoteClient{credentials: credentials})
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Set("manager", manager)
	c.Request = httptest.NewRequest("POST", "/api/update", strings.NewReader(`{"token_id":"new-id","token":"new-token"}`))
	c.Request.Header.Set("Content-Type", "application/json")

	postUpdateConfiguration(c)

	if recorder.Code != 200 {
		t.Fatalf("expected successful update, got status %d", recorder.Code)
	}
	updated := config.Get()
	if updated.Token.ID != "new-id" || updated.Token.Token != "new-token" {
		t.Fatalf("unexpected resolved credentials: %#v", updated.Token)
	}
	select {
	case got := <-credentials:
		if got != [2]string{"new-id", "new-token"} {
			t.Fatalf("unexpected client credentials: %#v", got)
		}
	default:
		t.Fatal("expected client credentials to be rotated")
	}
}

// Overlapping configuration updates are applied one at a time, so the global
// configuration and the Panel client always end up on the same token.
func TestPostUpdateConfigurationIsSerialized(t *testing.T) {
	t.Setenv("WINGS_TOKEN_ID", "")
	t.Setenv("WINGS_TOKEN", "")

	cfg, err := config.NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthenticationTokenId = "old-id"
	cfg.AuthenticationToken = "old-token"
	if err := cfg.ResolveToken(false); err != nil {
		t.Fatal(err)
	}
	config.Set(cfg)

	const updates = 25
	credentials := make(chan [2]string, updates)
	manager := server.NewEmptyManager(backupTestRemoteClient{credentials: credentials})

	var wg sync.WaitGroup
	for i := 0; i < updates; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Set("manager", manager)
			body := fmt.Sprintf(`{"token_id":"id-%d","token":"token-%d"}`, i, i)
			c.Request = httptest.NewRequest("POST", "/api/update", strings.NewReader(body))
			c.Request.Header.Set("Content-Type", "application/json")
			postUpdateConfiguration(c)
			if recorder.Code != 200 {
				t.Errorf("update %d: expected status 200, got %d", i, recorder.Code)
			}
		}(i)
	}
	wg.Wait()
	close(credentials)

	var last [2]string
	n := 0
	for got := range credentials {
		last = got
		n++
	}
	if n != updates {
		t.Fatalf("expected %d credential rotations, got %d", updates, n)
	}
	final := config.Get()
	if last != [2]string{final.Token.ID, final.Token.Token} {
		t.Fatalf("config is on %s/%s but the client was last given %s/%s", final.Token.ID, final.Token.Token, last[0], last[1])
	}
}
