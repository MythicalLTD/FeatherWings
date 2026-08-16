package websocket

import (
	"net/http"
	"testing"

	"github.com/mythicalltd/featherwings/config"
)

func TestWebsocketOriginAllowed(t *testing.T) {
	config.Set(&config.Configuration{
		AuthenticationToken: "test-token",
		PanelLocation:       "https://panel.example.com",
		AllowedOrigins:      []string{"https://extra.example.com"},
	})

	cases := []struct {
		name   string
		origin string
		host   string
		want   bool
	}{
		{name: "empty origin", origin: "", host: "node.example.com:8080", want: true},
		{name: "panel location", origin: "https://panel.example.com", host: "node.example.com:8080", want: true},
		{name: "allowed origins list", origin: "https://extra.example.com", host: "node.example.com:8080", want: true},
		{name: "calagopus daemon origin", origin: "https://node.example.com:8080", host: "node.example.com:8080", want: true},
		{name: "default https port", origin: "https://node.example.com", host: "node.example.com:443", want: true},
		{name: "vscode file scheme", origin: "vscode-file://vscode-app", host: "node.example.com:8080", want: true},
		{name: "foreign browser origin", origin: "https://evil.example.com", host: "node.example.com:8080", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}, Host: tc.host}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := websocketOriginAllowed(r); got != tc.want {
				t.Fatalf("websocketOriginAllowed() = %v, want %v", got, tc.want)
			}
		})
	}
}
