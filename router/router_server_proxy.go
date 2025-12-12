package router

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/gin-gonic/gin"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// isNginxInstalled checks if nginx is installed and available on the system.
// It checks if the nginx binary exists and if the nginx configuration directory exists.
func isNginxInstalled() bool {
	// Check if nginx binary exists
	if _, err := exec.LookPath("nginx"); err != nil {
		return false
	}

	// Check if nginx configuration directory exists
	if _, err := os.Stat("/etc/nginx"); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

// cleanupServerProxies removes all nginx proxy configurations and certificates
// that match the server's IP address. This is called during server deletion or transfer.
// Note: This is a best-effort cleanup and may not catch all proxies if multiple
// servers share the same IP address.
func cleanupServerProxies(serverIP string, logger *log.Entry) {
	if !isNginxInstalled() {
		return
	}

	// Read all nginx config files in sites-available
	configDir := "/etc/nginx/sites-available"
	entries, err := os.ReadDir(configDir)
	if err != nil {
		if logger != nil {
			logger.WithField("error", err).WithField("config_dir", configDir).Warn("failed to read nginx config directory during proxy cleanup")
		}
		return
	}

	// Pattern to match proxy_pass with the server IP
	proxyPassPattern := "proxy_pass http://" + serverIP + ":"
	removedAny := false

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) != ".conf" {
			continue
		}

		configPath := filepath.Join(configDir, name)
		content, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}

		// Check if this config file contains a proxy_pass to our server IP
		if !strings.Contains(string(content), proxyPassPattern) {
			continue
		}

		// Extract domain from filename (format: domain_port.conf)
		// Remove .conf extension and split by last underscore
		nameWithoutExt := name[:len(name)-5] // Remove .conf

		// Find last underscore to split domain and port
		lastUnderscore := strings.LastIndex(nameWithoutExt, "_")
		if lastUnderscore == -1 {
			continue
		}

		domain := nameWithoutExt[:lastUnderscore]

		// Remove nginx config files
		if err := os.RemoveAll(configPath); err != nil {
			if logger != nil {
				logger.WithField("error", err).WithField("config", configPath).Warn("failed to remove nginx config during proxy cleanup")
			}
		} else {
			removedAny = true
		}

		// Remove symlink in sites-enabled
		enabledPath := "/etc/nginx/sites-enabled/" + name
		if err := os.RemoveAll(enabledPath); err != nil {
			if logger != nil {
				logger.WithField("error", err).WithField("config", enabledPath).Warn("failed to remove nginx enabled config during proxy cleanup")
			}
		}

		// Remove certificate directory if it exists
		certDir := "/srv/server_certs/" + domain
		if _, err := os.Stat(certDir); err == nil {
			if err := os.RemoveAll(certDir); err != nil {
				if logger != nil {
					logger.WithField("error", err).WithField("cert_dir", certDir).Warn("failed to remove certificate directory during proxy cleanup")
				}
			} else if logger != nil {
				logger.WithField("cert_dir", certDir).Debug("removed certificate directory during proxy cleanup")
			}
		}

		if logger != nil {
			logger.WithField("domain", domain).WithField("config", name).Info("cleaned up proxy configuration during server cleanup")
		}
	}

	// Reload nginx if we removed any configs
	if removedAny {
		cmd := exec.Command("systemctl", "reload", "nginx")
		if err := cmd.Run(); err != nil {
			if logger != nil {
				logger.WithField("error", err).Warn("failed to reload nginx after proxy cleanup")
			}
		}
	}
}

type LetsEncryptUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *LetsEncryptUser) GetEmail() string {
	return u.Email
}
func (u LetsEncryptUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *LetsEncryptUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// postServerProxyCreate creates a reverse proxy configuration for a server.
// @Summary Create server proxy
// @Tags Server Proxy
// @Accept json
// @Produce json
// @Param server path string true "Server identifier"
// @Param payload body object true "Proxy configuration" example({"domain":"example.com","ip":"127.0.0.1","port":"25565","ssl":false,"use_lets_encrypt":false,"client_email":"","ssl_cert":"","ssl_key":""})
// @Success 202 "Accepted"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse "Service Unavailable - nginx not installed"
// @Security NodeToken
// @Router /api/servers/{server}/proxy/create [post]
func postServerProxyCreate(c *gin.Context) {
	s := ExtractServer(c)

	// Check if nginx is installed before proceeding
	if !isNginxInstalled() {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"error":      "Looks like nginx is not installed. Please contact your system admin to fix this issue.",
			"request_id": c.Writer.Header().Get("X-Request-Id"),
		})
		return
	}

	var data struct {
		Domain         string `json:"domain"`
		IP             string `json:"ip"`
		Port           string `json:"port"`
		Ssl            bool   `json:"ssl"`
		UseLetsEncrypt bool   `json:"use_lets_encrypt"`
		ClientEmail    string `json:"client_email"`
		SslCert        string `json:"ssl_cert"`
		SslKey         string `json:"ssl_key"`
	}

	if err := c.BindJSON(&data); err != nil {
		return
	}

	nginxconfig := []byte(`server {
		listen 80;
		server_name ` + data.Domain + `;

		location / {
			proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
			proxy_set_header Host $http_host;
			proxy_pass http://` + data.IP + `:` + data.Port + `;
		}

		location /.well-known/acme-challenge/ {
			proxy_set_header Host $host;
			proxy_pass http://127.0.0.1:81$request_uri;
		}
	}`)

	err := os.WriteFile("/etc/nginx/sites-available/"+data.Domain+"_"+data.Port+".conf", nginxconfig, 0644)
	if err != nil {
		s.Log().WithField("error", err).Error("failed to write nginx config " + data.Domain + "_" + data.Port + ".conf")
	}

	lncmd := exec.Command(
		"ln",
		"-s",
		"/etc/nginx/sites-available/"+data.Domain+"_"+data.Port+".conf",
		"/etc/nginx/sites-enabled/"+data.Domain+"_"+data.Port+".conf",
	)
	lncmd.Run()

	restartcmd := exec.Command("systemctl", "reload", "nginx")
	restartcmd.Run()

	var certfile []byte
	var keyfile []byte

	certPath := "/srv/server_certs/" + data.Domain + "/cert.pem"
	keyPath := "/srv/server_certs/" + data.Domain + "/key.pem"

	if data.Ssl {

		if data.UseLetsEncrypt {
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				s.Log().WithField("error", err).Error("failed to generate private key for Let's Encrypt")
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": "Failed to generate private key",
				})
				return
			}

			letsEncryptUser := LetsEncryptUser{
				Email: data.ClientEmail,
				key:   privateKey,
			}

			config := lego.NewConfig(&letsEncryptUser)
			config.Certificate.KeyType = certcrypto.RSA2048

			client, err := lego.NewClient(config)
			if err != nil {
				s.Log().WithField("error", err).Error("failed to create lego client")
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": "Failed to request certificate",
				})
				return
			}

			err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "81"))
			if err != nil {
				s.Log().WithField("error", err).Error("failed to set HTTP01 provider")
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": "Failed to request certificate",
				})
				return
			}

			reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
			if err != nil {
				s.Log().WithField("error", err).Error("failed to register account")
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": "Failed to request certificate",
				})
				return
			}
			letsEncryptUser.Registration = reg

			request := certificate.ObtainRequest{
				Domains: []string{data.Domain},
				Bundle:  true,
			}

			cert, err := client.Certificate.Obtain(request)
			if err != nil {
				s.Log().WithField("error", err).Error("failed to obtain certificate")
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": "Failed to request certificate",
				})
				return
			}

			certfile = []byte(cert.Certificate)
			keyfile = []byte(cert.PrivateKey)
		} else {
			certfile = []byte(data.SslCert)
			keyfile = []byte(data.SslKey)
		}

		if err := os.MkdirAll(filepath.Dir(certPath), os.ModeDir); err != nil {
			s.Log().WithField("error", err).Error("failed to create " + filepath.Dir(certPath))
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Failed to save certificate",
			})
			return
		}

		if err := os.MkdirAll(filepath.Dir(keyPath), os.ModeDir); err != nil {
			s.Log().WithField("error", err).Error("failed to create " + filepath.Dir(keyPath))
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Failed to save certificate",
			})
			return
		}

		if err := os.WriteFile(certPath, certfile, 0644); err != nil {
			s.Log().WithField("error", err).Error("failed to write " + certPath)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Failed to save certificate",
			})
			return
		}

		if err := os.WriteFile(keyPath, keyfile, 0644); err != nil {
			s.Log().WithField("error", err).Error("failed to write " + keyPath)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Failed to save certificate",
			})
			return
		}

		nginxconfig = []byte(`server {
	listen 80;
	server_name ` + data.Domain + `;
	return 301 https://$server_name$request_uri;
}

server {
	listen 443 ssl http2;
	server_name ` + data.Domain + `;

	ssl_certificate ` + certPath + `;
	ssl_certificate_key ` + keyPath + `;
	ssl_session_cache shared:SSL:10m;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
	ssl_prefer_server_ciphers on;

	location / {
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header Host $http_host;
		proxy_pass http://` + data.IP + `:` + data.Port + `;
	}

	location /.well-known/acme-challenge/ {
		proxy_set_header Host $host;
		proxy_pass http://127.0.0.1:81$request_uri;
	}
}`)

		err := os.WriteFile("/etc/nginx/sites-available/"+data.Domain+"_"+data.Port+".conf", nginxconfig, 0644)
		if err != nil {
			s.Log().WithField("error", err).Error("failed to write nginx config " + data.Domain + "_" + data.Port + ".conf")
		}

		restartcmd := exec.Command("systemctl", "reload", "nginx")
		restartcmd.Run()
	}

	c.Status(http.StatusAccepted)
}

// postServerProxyDelete deletes a reverse proxy configuration for a server.
// @Summary Delete server proxy
// @Tags Server Proxy
// @Accept json
// @Produce json
// @Param server path string true "Server identifier"
// @Param payload body object true "Proxy deletion request" example({"domain":"example.com","port":"25565"})
// @Success 202 "Accepted"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse "Service Unavailable - nginx not installed"
// @Security NodeToken
// @Router /api/servers/{server}/proxy/delete [post]
func postServerProxyDelete(c *gin.Context) {
	s := ExtractServer(c)

	// Check if nginx is installed before proceeding
	if !isNginxInstalled() {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"error":      "Looks like nginx is not installed. Please contact your system admin to fix this issue.",
			"request_id": c.Writer.Header().Get("X-Request-Id"),
		})
		return
	}

	var data struct {
		Domain string `json:"domain"`
		Port   string `json:"port"`
	}

	if err := c.BindJSON(&data); err != nil {
		return
	}

	err := os.RemoveAll("/etc/nginx/sites-available/" + data.Domain + "_" + data.Port + ".conf")
	if err != nil {
		s.Log().WithField("error", err).Error("failed to remove nginx config sites-available/" + data.Domain + "_" + data.Port + ".conf")
	}

	err = os.RemoveAll("/etc/nginx/sites-enabled/" + data.Domain + "_" + data.Port + ".conf")
	if err != nil {
		s.Log().WithField("error", err).Error("failed to remove nginx config sites-enabled/" + data.Domain + "_" + data.Port + ".conf")
	}

	// Remove SSL certificate directory if it exists
	certDir := "/srv/server_certs/" + data.Domain
	if _, err := os.Stat(certDir); err == nil {
		if err := os.RemoveAll(certDir); err != nil {
			s.Log().WithField("error", err).WithField("cert_dir", certDir).Warn("failed to remove certificate directory")
		} else {
			s.Log().WithField("cert_dir", certDir).Info("removed certificate directory")
		}
	}

	cmd := exec.Command("systemctl", "reload", "nginx")
	cmd.Run()

	c.Status(http.StatusAccepted)
}
