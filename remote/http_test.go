package remote

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithCustomHeaders(t *testing.T) {
	// Test that custom headers option function can be created without error
	customHeaders := map[string]string{
		"CF-Access-Client-Id":     "test-client-id",
		"CF-Access-Client-Secret": "test-client-secret",
		"X-Custom-Header":         "custom-value",
	}

	// Test that the option function can be created
	option := WithCustomHeaders(customHeaders)
	if option == nil {
		t.Fatal("WithCustomHeaders should not return nil")
	}

	// Test that we can create a client with custom headers without error
	client := New(
		"https://example.com",
		WithCredentials("test-id", "test-token"),
		WithCustomHeaders(customHeaders),
	)

	if client == nil {
		t.Fatal("client should not be nil")
	}
}

func TestWithCustomHeadersNil(t *testing.T) {
	// Test that nil custom headers are handled gracefully
	option := WithCustomHeaders(nil)
	if option == nil {
		t.Fatal("WithCustomHeaders should not return nil even with nil input")
	}

	// Test that we can create a client with nil custom headers without error
	client := New(
		"https://example.com",
		WithCredentials("test-id", "test-token"),
		WithCustomHeaders(nil),
	)

	if client == nil {
		t.Fatal("client should not be nil")
	}
}

func TestWithCustomHeadersEmpty(t *testing.T) {
	// Test that empty custom headers are handled gracefully
	option := WithCustomHeaders(map[string]string{})
	if option == nil {
		t.Fatal("WithCustomHeaders should not return nil even with empty map")
	}

	// Test that we can create a client with empty custom headers without error
	client := New(
		"https://example.com",
		WithCredentials("test-id", "test-token"),
		WithCustomHeaders(map[string]string{}),
	)

	if client == nil {
		t.Fatal("client should not be nil")
	}
}

func TestSetCredentialsRotatesAuthorization(t *testing.T) {
	var authorization []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		authorization = append(authorization, r.Header.Get("Authorization"))
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, WithCredentials("old-id", "old-token")).(*client)
	if _, err := c.requestOnce(context.Background(), http.MethodGet, "/test", nil); err != nil {
		t.Fatal(err)
	}
	c.SetCredentials("rotated-id", "rotated-token")
	if _, err := c.requestOnce(context.Background(), http.MethodGet, "/test", nil); err != nil {
		t.Fatal(err)
	}

	want := []string{"Bearer old-id.old-token", "Bearer rotated-id.rotated-token"}
	if len(authorization) != len(want) || authorization[0] != want[0] || authorization[1] != want[1] {
		t.Fatalf("unexpected authorization headers: %v", authorization)
	}
}
