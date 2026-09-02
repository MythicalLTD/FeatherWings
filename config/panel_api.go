package config

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"emperror.dev/errors"
)

const panelAPITimeout = 30 * time.Second

// PanelAPI is a minimal FeatherPanel admin API client authenticated with an API key.
type PanelAPI struct {
	BaseURL       string
	APIKey        string
	AllowInsecure bool
	HTTPClient    *http.Client
}

// PanelLocation is a game server location from the panel.
type PanelLocation struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Short       string `json:"short"`
	Type        string `json:"type"`
	Description string `json:"description"`
	FlagCode    string `json:"flag_code"`
}

// CreatePanelLocationRequest is the body for PUT /api/admin/locations.
type CreatePanelLocationRequest struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	FlagCode    string `json:"flag_code,omitempty"`
}

// PanelNode is the node payload returned when creating a node.
type PanelNode struct {
	ID             int    `json:"id"`
	UUID           string `json:"uuid"`
	Name           string `json:"name"`
	FQDN           string `json:"fqdn"`
	LocationID     int    `json:"location_id"`
	DaemonTokenID  string `json:"daemon_token_id"`
	DaemonToken    string `json:"daemon_token"`
	DaemonListen   int    `json:"daemonListen"`
	DaemonType     string `json:"daemon_type"`
	PublicIPv4     string `json:"public_ip_v4"`
}

// CreatePanelNodeRequest is the body for PUT /api/admin/nodes.
type CreatePanelNodeRequest struct {
	Name               string  `json:"name"`
	Description        string  `json:"description,omitempty"`
	FQDN               string  `json:"fqdn"`
	LocationID         int     `json:"location_id"`
	Public             int     `json:"public"`
	Scheme             string  `json:"scheme"`
	BehindProxy        int     `json:"behind_proxy"`
	MaintenanceMode    int     `json:"maintenance_mode"`
	Memory             int     `json:"memory"`
	MemoryOverallocate int     `json:"memory_overallocate"`
	Disk               int     `json:"disk"`
	DiskOverallocate   int     `json:"disk_overallocate"`
	UploadSize         int     `json:"upload_size"`
	DaemonListen       int     `json:"daemonListen"`
	DaemonSFTP         int     `json:"daemonSFTP"`
	FastDLPort         int     `json:"fastdl_port"`
	DaemonBase         string  `json:"daemonBase"`
	DaemonType         string  `json:"daemon_type,omitempty"`
	PublicIPv4         *string `json:"public_ip_v4"`
	PublicIPv6         *string `json:"public_ip_v6"`
	SFTPSubdomain      *string `json:"sftp_subdomain"`
}

// PanelAPIClientInfo is returned by POST /api/user/api-clients/validate.
type PanelAPIClientInfo struct {
	Valid      bool   `json:"valid"`
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Username   string `json:"-"`
	UserEmail  string `json:"-"`
}

type panelEnvelope struct {
	Success      bool            `json:"success"`
	Message      string          `json:"message"`
	Data         json.RawMessage `json:"data"`
	Error        bool            `json:"error"`
	ErrorMessage string          `json:"error_message"`
	ErrorCode    string          `json:"error_code"`
}

// NewPanelAPI creates a panel API client with a normalized base URL.
func NewPanelAPI(baseURL, apiKey string, allowInsecure bool) *PanelAPI {
	return &PanelAPI{
		BaseURL:       NormalizePanelURL(baseURL),
		APIKey:        strings.TrimSpace(apiKey),
		AllowInsecure: allowInsecure,
		HTTPClient:    newPanelHTTPClient(allowInsecure),
	}
}

// NormalizePanelURL returns the panel origin (scheme + host, optional port) with no path or query.
func NormalizePanelURL(baseURL string) string {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return ""
	}

	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return strings.TrimRight(baseURL, "/")
	}

	return parsed.Scheme + "://" + parsed.Host
}

func newPanelHTTPClient(allowInsecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if allowInsecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &http.Client{
		Timeout:   panelAPITimeout,
		Transport: transport,
	}
}

// ValidateAPIClient checks that an API key is valid via POST /api/user/api-clients/validate.
func ValidateAPIClient(ctx context.Context, baseURL, publicKey string, allowInsecure bool) (*PanelAPIClientInfo, error) {
	body, err := json.Marshal(map[string]string{"public_key": publicKey})
	if err != nil {
		return nil, err
	}

	client := newPanelHTTPClient(allowInsecure)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		NormalizePanelURL(baseURL)+"/api/user/api-clients/validate",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "panel: failed to validate API key")
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "panel: failed to read validate response")
	}

	var envelope panelEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, errors.Wrap(err, "panel: invalid validate response")
	}
	if !envelope.Success {
		return nil, panelAPIError(envelope, "panel rejected the API key")
	}

	var data struct {
		Valid     bool `json:"valid"`
		APIClient struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"api_client"`
		User struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		return nil, errors.Wrap(err, "panel: invalid validate payload")
	}
	if !data.Valid {
		return nil, errors.New("panel: API key is not valid")
	}

	return &PanelAPIClientInfo{
		Valid:     true,
		ID:        data.APIClient.ID,
		Name:      data.APIClient.Name,
		Username:  data.User.Username,
		UserEmail: data.User.Email,
	}, nil
}

// PanelSystemInfo contains public panel metadata from GET /api/system/settings.
type PanelSystemInfo struct {
	AppName    string
	AppURL     string
	AppVersion string
	CoreVersion string
	Hostname   string
}

// GetSystemSettings loads public panel settings from GET /api/system/settings.
func (api *PanelAPI) GetSystemSettings(ctx context.Context) (*PanelSystemInfo, error) {
	var data struct {
		Settings map[string]string `json:"settings"`
		Core     struct {
			Version  string `json:"version"`
			Hostname string `json:"hostname"`
		} `json:"core"`
	}
	if err := api.getJSON(ctx, "/api/system/settings", &data); err != nil {
		return nil, err
	}

	info := &PanelSystemInfo{
		AppName:     strings.TrimSpace(data.Settings["app_name"]),
		AppURL:      strings.TrimSpace(data.Settings["app_url"]),
		AppVersion:  strings.TrimSpace(data.Settings["app_version"]),
		CoreVersion: strings.TrimSpace(data.Core.Version),
		Hostname:    strings.TrimSpace(data.Core.Hostname),
	}
	if info.AppName == "" {
		info.AppName = "FeatherPanel"
	}
	if info.AppURL == "" {
		info.AppURL = api.BaseURL
	}
	return info, nil
}

// DeleteAPIClient removes an API key via DELETE /api/user/api-clients/{id}.
func (api *PanelAPI) DeleteAPIClient(ctx context.Context, id int) error {
	if id <= 0 {
		return errors.New("panel: invalid API client id")
	}
	return api.requestJSON(ctx, http.MethodDelete, fmt.Sprintf("/api/user/api-clients/%d", id), nil, nil)
}

// ListGameLocations returns game locations from GET /api/admin/locations.
func (api *PanelAPI) ListGameLocations(ctx context.Context) ([]PanelLocation, error) {
	values := url.Values{}
	values.Set("page", "1")
	values.Set("limit", "100")
	values.Set("type", "game")

	var data struct {
		Locations []PanelLocation `json:"locations"`
	}
	if err := api.getJSON(ctx, "/api/admin/locations?"+values.Encode(), &data); err != nil {
		return nil, err
	}
	return data.Locations, nil
}

// CreateLocation registers a game location via PUT /api/admin/locations.
func (api *PanelAPI) CreateLocation(ctx context.Context, req CreatePanelLocationRequest) (*PanelLocation, error) {
	if strings.TrimSpace(req.Type) == "" {
		req.Type = "game"
	}

	var data struct {
		Location PanelLocation `json:"location"`
	}
	if err := api.putJSON(ctx, "/api/admin/locations", req, &data); err != nil {
		return nil, err
	}
	if data.Location.ID == 0 {
		return nil, errors.New("panel: location create response did not include a location id")
	}
	return &data.Location, nil
}

// CreateNode registers a new node via PUT /api/admin/nodes.
func (api *PanelAPI) CreateNode(ctx context.Context, req CreatePanelNodeRequest) (*PanelNode, error) {
	applyCreatePanelNodeDefaults(&req)

	var data struct {
		Node PanelNode `json:"node"`
	}
	if err := api.putJSON(ctx, "/api/admin/nodes", req, &data); err != nil {
		return nil, err
	}
	if data.Node.ID == 0 {
		return nil, errors.New("panel: node create response did not include a node id")
	}
	return &data.Node, nil
}

// GetNodeJoinData fetches base64 join-data from GET /api/admin/nodes/{id}/setup-command.
func (api *PanelAPI) GetNodeJoinData(ctx context.Context, nodeID int) (string, error) {
	var data struct {
		JoinData string `json:"join_data"`
		PanelURL string `json:"panel_url"`
	}
	if err := api.getJSON(ctx, fmt.Sprintf("/api/admin/nodes/%d/setup-command", nodeID), &data); err != nil {
		return "", err
	}
	joinData := strings.TrimSpace(data.JoinData)
	if joinData == "" {
		return "", errors.New("panel: setup command did not include join_data")
	}
	return joinData, nil
}

func (api *PanelAPI) getJSON(ctx context.Context, path string, dest any) error {
	return api.requestJSON(ctx, http.MethodGet, path, nil, dest)
}

func (api *PanelAPI) putJSON(ctx context.Context, path string, payload any, dest any) error {
	return api.requestJSON(ctx, http.MethodPut, path, payload, dest)
}

func (api *PanelAPI) requestJSON(ctx context.Context, method, path string, payload any, dest any) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, api.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+api.APIKey)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := api.HTTPClient
	if client == nil {
		client = newPanelHTTPClient(api.AllowInsecure)
	}

	res, err := client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "panel: %s %s failed", method, path)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "panel: failed to read response body")
	}

	var envelope panelEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return errors.Wrapf(err, "panel: invalid JSON response from %s", path)
	}
	if !envelope.Success {
		return panelAPIError(envelope, fmt.Sprintf("panel: %s %s failed", method, path))
	}
	if dest == nil {
		return nil
	}
	if err := json.Unmarshal(envelope.Data, dest); err != nil {
		return errors.Wrapf(err, "panel: invalid data payload from %s", path)
	}
	return nil
}

func applyCreatePanelNodeDefaults(req *CreatePanelNodeRequest) {
	if strings.TrimSpace(req.DaemonType) == "" {
		req.DaemonType = "featherwings"
	}
	if strings.TrimSpace(req.Scheme) == "" {
		req.Scheme = "https"
	}
	if strings.TrimSpace(req.DaemonBase) == "" {
		req.DaemonBase = "/var/lib/featherpanel/volumes"
	}
	if req.DaemonListen == 0 {
		req.DaemonListen = 8443
	}
	if req.DaemonSFTP == 0 {
		req.DaemonSFTP = 2022
	}
	if req.FastDLPort == 0 {
		req.FastDLPort = 80
	}
	if req.UploadSize == 0 {
		req.UploadSize = 100
	}
}

func panelAPIError(envelope panelEnvelope, fallback string) error {
	message := strings.TrimSpace(envelope.ErrorMessage)
	if message == "" {
		message = strings.TrimSpace(envelope.Message)
	}
	if message == "" {
		message = fallback
	}
	if code := strings.TrimSpace(envelope.ErrorCode); code != "" {
		return errors.Errorf("%s (%s)", message, code)
	}
	return errors.New(message)
}
