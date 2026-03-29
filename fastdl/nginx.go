package fastdl

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"emperror.dev/errors"
	"github.com/apex/log"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/server"
)

// GenerateNginxConfig generates an nginx configuration file for FastDL based on enabled servers.
func GenerateNginxConfig(manager *server.Manager) error {
	cfg := config.Get()
	fastdlCfg := cfg.System.FastDL

	// Check if FastDL is enabled
	if !fastdlCfg.Enabled {
		return nil
	}

	// Check if nginx is installed
	if !IsNginxInstalled() {
		return errors.New("nginx is not installed or not available")
	}

	// Validate that the FastDL port does not conflict with the Wings API port.
	if fastdlCfg.Port == cfg.Api.Port {
		return errors.Errorf("fastdl: configured port (%d) conflicts with Wings API port — please use a different port", fastdlCfg.Port)
	}

	// Get all servers with FastDL enabled
	var enabledServers []serverConfig
	for _, srv := range manager.All() {
		srvCfg := srv.Config()
		if srvCfg.FastDL.Enabled {
			enabledServers = append(enabledServers, serverConfig{
				UUID:      srv.ID(),
				Directory: srvCfg.FastDL.Directory,
			})
		}
	}

	if len(enabledServers) == 0 {
		log.Debug("fastdl: no servers with FastDL enabled, skipping nginx config generation")
		return nil
	}

	// Build nginx config
	nginxConfig := buildNginxConfig(cfg, enabledServers)

	// Write config file
	configPath := fastdlCfg.NginxConfigPath
	if configPath == "" {
		configPath = "/etc/nginx/sites-available/featherwings-fastdl"
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return errors.Wrap(err, "fastdl: failed to create nginx config directory")
	}

	if err := os.WriteFile(configPath, []byte(nginxConfig), 0o644); err != nil {
		return errors.Wrap(err, "fastdl: failed to write nginx config")
	}

	log.WithField("path", configPath).Info("fastdl: nginx configuration generated")

	// Create symlink to sites-enabled if it doesn't exist
	sitesEnabled := "/etc/nginx/sites-enabled/featherwings-fastdl"
	if _, err := os.Lstat(sitesEnabled); err != nil {
		if os.IsNotExist(err) {
			if err := os.Symlink(configPath, sitesEnabled); err != nil {
				log.WithError(err).Warn("fastdl: failed to create nginx symlink, you may need to enable it manually")
			} else {
				log.WithField("link", sitesEnabled).Info("fastdl: nginx symlink created")
			}
		}
	}

	// Reload nginx so the new configuration takes effect.
	if err := ReloadNginx(); err != nil {
		log.WithError(err).Warn("fastdl: nginx config written but reload failed — please reload nginx manually")
	}

	return nil
}

type serverConfig struct {
	UUID      string
	Directory string
}

// buildNginxConfig builds the nginx configuration content matching the user's template exactly.
// Uses default blocked extensions: .sma, .amxx, .sp, .smx, .cfg, .ini, .log, .bak, .dat, .sql, .sq3, .so, .dll, .php, .zip, .rar, .jar, .sh
// Uses default blocked directories: addons, cfg, logs
func buildNginxConfig(cfg *config.Configuration, servers []serverConfig) string {
	fastdlCfg := cfg.System.FastDL

	// Determine server name - use panel location hostname or default
	serverName := "example.website.ro" // Default from user's example
	if panelURL := cfg.PanelLocation; panelURL != "" {
		// Extract hostname from panel URL
		panelURL = strings.TrimPrefix(panelURL, "http://")
		panelURL = strings.TrimPrefix(panelURL, "https://")
		if idx := strings.Index(panelURL, "/"); idx > 0 {
			serverName = panelURL[:idx]
		} else {
			serverName = panelURL
		}
	}

	// Build the config exactly as the user's template - no SSL, simple structure
	// Uses default blocked extensions and directories from the nginx config
	config := fmt.Sprintf(`server {
    listen %d;
    listen [::]:%d;

	root %s;
	index index.html;

	server_name %s;

	location / {
		# First attempt to serve request as file, then
		# as directory, then fall back to displaying a 404.
		try_files $uri $uri/ =404;
        
		# Comment this line if dont want to list files (only after checking that your fastdl works)
		autoindex on;
	}
	
	location ~\.(sma|amxx|sp|smx|cfg|ini|log|bak|dat|sql|sq3|so|dll|php|zip|rar|jar|sh)$ {
		return 403;
	}
    
	location ~ /(addons|cfg|logs) {
  		deny all;
	}
}
`, fastdlCfg.Port, fastdlCfg.Port, cfg.System.Data, serverName)

	return config
}

// ReloadNginx attempts to reload nginx configuration.
func ReloadNginx() error {
	// Try systemctl reload first (preferred on systemd systems).
	cmd := exec.Command("systemctl", "reload", "nginx")
	if _, err := cmd.CombinedOutput(); err != nil {
		// Fall back to nginx -s reload.
		cmd2 := exec.Command("nginx", "-s", "reload")
		if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
			return errors.Wrapf(err2, "fastdl: failed to reload nginx: %s", strings.TrimSpace(string(out2)))
		}
	}
	log.Info("fastdl: nginx reloaded successfully")
	return nil
}
