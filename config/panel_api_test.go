package config

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateAPIClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/api-clients/validate" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"valid": true,
				"api_client": map[string]any{
					"id":   42,
					"name": "FeatherWings CLI",
				},
				"user": map[string]any{
					"username": "admin",
					"email":    "admin@example.com",
				},
			},
		})
	}))
	defer server.Close()

	info, err := ValidateAPIClient(context.Background(), server.URL, "fp_test", false)
	if err != nil {
		t.Fatalf("ValidateAPIClient() error = %v", err)
	}
	if !info.Valid || info.Username != "admin" || info.ID != 42 {
		t.Fatalf("unexpected validate result: %+v", info)
	}
}

func TestPanelAPIDeleteAPIClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api/user/api-clients/42" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    nil,
		})
	}))
	defer server.Close()

	api := NewPanelAPI(server.URL, "fp_test", false)
	if err := api.DeleteAPIClient(context.Background(), 42); err != nil {
		t.Fatalf("DeleteAPIClient() error = %v", err)
	}
}

func TestPanelAPICreateNodeAndJoinData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/api/admin/nodes":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data": map[string]any{
					"node": map[string]any{
						"id":              7,
						"uuid":            "node-uuid",
						"name":            "Test Node",
						"fqdn":            "node.example.com",
						"daemon_token_id": "token-id",
						"daemon_token":    "secret",
						"daemonListen":    8443,
						"daemon_type":     "featherwings",
						"location_id":     1,
					},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/admin/nodes/7/setup-command":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data": map[string]any{
					"join_data": "YmFzZTY0",
				},
			})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	api := NewPanelAPI(server.URL, "fp_test", false)
	ctx := context.Background()

	node, err := api.CreateNode(ctx, CreatePanelNodeRequest{
		Name:       "Test Node",
		FQDN:       "node.example.com",
		LocationID: 1,
	})
	if err != nil {
		t.Fatalf("CreateNode() error = %v", err)
	}
	if node.ID != 7 || node.UUID != "node-uuid" {
		t.Fatalf("unexpected node: %+v", node)
	}

	joinData, err := api.GetNodeJoinData(ctx, node.ID)
	if err != nil {
		t.Fatalf("GetNodeJoinData() error = %v", err)
	}
	if joinData != "YmFzZTY0" {
		t.Fatalf("GetNodeJoinData() = %q", joinData)
	}
}

func TestPanelAPIListAndCreateLocations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/admin/locations":
			if r.URL.Query().Get("type") != "game" {
				t.Fatalf("expected type=game query, got %q", r.URL.Query().Get("type"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data": map[string]any{
					"locations": []map[string]any{
						{"id": 1, "name": "Location-1", "type": "game"},
					},
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/api/admin/locations":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data": map[string]any{
					"location": map[string]any{
						"id":   166,
						"name": "dasdas",
						"type": "game",
					},
				},
			})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	api := NewPanelAPI(server.URL, "fp_test", false)
	ctx := context.Background()

	locations, err := api.ListGameLocations(ctx)
	if err != nil {
		t.Fatalf("ListGameLocations() error = %v", err)
	}
	if len(locations) != 1 || locations[0].ID != 1 {
		t.Fatalf("unexpected locations: %+v", locations)
	}

	created, err := api.CreateLocation(ctx, CreatePanelLocationRequest{
		Name:        "dasdas",
		Type:        "game",
		Description: "dasdasd",
		FlagCode:    "al",
	})
	if err != nil {
		t.Fatalf("CreateLocation() error = %v", err)
	}
	if created.ID != 166 {
		t.Fatalf("unexpected created location: %+v", created)
	}
}

func TestPanelAPIGetSystemSettings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/system/settings" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"settings": map[string]string{
					"app_name":    "FeatherPanel",
					"app_url":     "http://212.87.213.118:8721",
					"app_version": "1.4.0",
				},
				"core": map[string]string{
					"version":  "v1.4.0",
					"hostname": "debian",
				},
			},
		})
	}))
	defer server.Close()

	api := NewPanelAPI(server.URL, "fp_test", false)
	info, err := api.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings() error = %v", err)
	}
	if info.AppName != "FeatherPanel" || info.AppVersion != "1.4.0" || info.CoreVersion != "v1.4.0" {
		t.Fatalf("unexpected settings: %+v", info)
	}
	if info.AppURL != "http://212.87.213.118:8721" || info.Hostname != "debian" {
		t.Fatalf("unexpected app url/hostname: %+v", info)
	}
}

func TestNormalizePanelURL(t *testing.T) {
	tests := map[string]string{
		"https://panel.example.com///":                                              "https://panel.example.com",
		"https://panel.example.com/admin/nodes/8/edit?tab=wings":                    "https://panel.example.com",
		"http://212.87.213.118:8721/api/remote/config":                            "http://212.87.213.118:8721",
		"https://testingpanel.mythical.systems/dashboard/account/oauth2/api/new?x=1": "https://testingpanel.mythical.systems",
	}
	for input, want := range tests {
		if got := NormalizePanelURL(input); got != want {
			t.Fatalf("NormalizePanelURL(%q) = %q, want %q", input, got, want)
		}
	}
}
