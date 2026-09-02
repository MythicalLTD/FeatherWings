package config

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"emperror.dev/errors"
	"gopkg.in/yaml.v2"

	"github.com/mythicalltd/featherwings/system"
)

// JoinBootstrap is the minimal YAML embedded in panel join-data. FeatherWings uses
// it to authenticate against GET /api/remote/config and write the runtime config.
type JoinBootstrap struct {
	UUID    string `yaml:"uuid"`
	TokenID string `yaml:"token_id"`
	Token   string `yaml:"token"`
	Remote  string `yaml:"remote"`
	Api     struct {
		Port int `yaml:"port"`
	} `yaml:"api"`
	RemoteQuery RemoteQueryConfiguration `yaml:"remote_query"`
}

// ParseJoinBootstrap decodes bootstrap YAML from join-data.
func ParseJoinBootstrap(raw []byte) (*JoinBootstrap, error) {
	var bootstrap JoinBootstrap
	if err := yaml.Unmarshal(raw, &bootstrap); err != nil {
		return nil, errors.Wrap(err, "join-data: invalid YAML")
	}
	return &bootstrap, nil
}

// ValidateJoin ensures the bootstrap contains enough data to contact the panel.
func (b *JoinBootstrap) ValidateJoin() error {
	if strings.TrimSpace(b.UUID) == "" {
		return errors.New("join-data: uuid is required")
	}
	if strings.TrimSpace(b.TokenID) == "" {
		return errors.New("join-data: token_id is required")
	}
	if strings.TrimSpace(b.Token) == "" {
		return errors.New("join-data: token is required")
	}
	if strings.TrimSpace(b.Remote) == "" {
		return errors.New("join-data: remote panel URL is required")
	}
	return nil
}

// IsFullWingsConfig reports whether join-data already contains a complete config.yml.
func IsFullWingsConfig(raw []byte) bool {
	var fields map[string]interface{}
	if err := yaml.Unmarshal(raw, &fields); err != nil {
		return false
	}
	_, hasSystem := fields["system"]
	_, hasToken := fields["token_id"]
	return hasSystem && hasToken
}

// VerifyJoinCredentials checks the bootstrap token against the panel health endpoint.
func VerifyJoinCredentials(ctx context.Context, bootstrap *JoinBootstrap, allowInsecure bool) error {
	if bootstrap == nil {
		return errors.New("join-data: bootstrap is nil")
	}
	if err := bootstrap.ValidateJoin(); err != nil {
		return err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if allowInsecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	timeout := bootstrap.RemoteQuery.Timeout
	if timeout <= 0 {
		timeout = 30
	}

	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
	}

	panel := strings.TrimRight(strings.TrimSpace(bootstrap.Remote), "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, panel+"/api/remote/health", nil)
	if err != nil {
		return errors.Wrap(err, "join-data: failed to create health request")
	}

	req.Header.Set("User-Agent", fmt.Sprintf("FeatherPanel Wings/v%s (id:%s)", system.Version, bootstrap.TokenID))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s.%s", bootstrap.TokenID, bootstrap.Token))
	for key, value := range bootstrap.RemoteQuery.CustomHeaders {
		req.Header.Set(key, value)
	}

	res, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "join-data: failed to contact panel")
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "join-data: failed to read health response")
	}

	switch res.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return errors.New("panel rejected the node token — regenerate the daemon key in FeatherPanel")
	default:
		return errors.Errorf("panel health check returned HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
}

// FetchRuntimeConfigYAML downloads the runtime config from the panel using bootstrap credentials.
func FetchRuntimeConfigYAML(ctx context.Context, bootstrap *JoinBootstrap, allowInsecure bool) ([]byte, error) {
	if bootstrap == nil {
		return nil, errors.New("join-data: bootstrap is nil")
	}
	if err := bootstrap.ValidateJoin(); err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if allowInsecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	timeout := bootstrap.RemoteQuery.Timeout
	if timeout <= 0 {
		timeout = 30
	}

	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
	}

	panel := strings.TrimRight(strings.TrimSpace(bootstrap.Remote), "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, panel+"/api/remote/config", nil)
	if err != nil {
		return nil, errors.Wrap(err, "join-data: failed to create config request")
	}

	req.Header.Set("User-Agent", fmt.Sprintf("FeatherPanel Wings/v%s (id:%s)", system.Version, bootstrap.TokenID))
	req.Header.Set("Accept", "application/x-yaml, application/yaml, text/yaml, */*")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s.%s", bootstrap.TokenID, bootstrap.Token))
	for key, value := range bootstrap.RemoteQuery.CustomHeaders {
		req.Header.Set(key, value)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "join-data: failed to fetch runtime config from panel")
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "join-data: failed to read runtime config response")
	}

	switch res.StatusCode {
	case http.StatusOK:
		if len(strings.TrimSpace(string(body))) == 0 {
			return nil, errors.New("join-data: panel returned an empty config")
		}
		return body, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, errors.New("join-data: panel rejected the node credentials")
	default:
		return nil, errors.Errorf("join-data: panel returned HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
}
