package router

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/mythicalltd/featherwings/config"
)

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

// isNginxInstalled checks if nginx is installed and available on the system.
func isNginxInstalled() bool {
	_, err := exec.LookPath("nginx")
	return err == nil
}

// checkNginxRequirement checks if nginx is required and installed.
// Returns an error message if nginx is required but not installed.
func checkNginxRequirement() (bool, string) {
	cfg := config.Get()
	if !cfg.Api.ReverseProxy.Enabled {
		return true, ""
	}

	if !isNginxInstalled() {
		return false, "Reverse proxy is enabled in configuration, but nginx is not installed. Please install nginx for this feature to work. On Debian/Ubuntu: apt-get install nginx, on RHEL/CentOS: yum install nginx"
	}

	return true, ""
}

// postServerProxyCreate creates a reverse proxy configuration for a server using nginx.
// @Summary Create server reverse proxy
// @Description Creates an nginx reverse proxy configuration for a server. Requires nginx to be installed when reverse proxy is enabled in configuration.
// @Tags Servers
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body object true "Proxy configuration" example({"domain":"example.com","ip":"127.0.0.1","port":"25565","ssl":false,"use_lets_encrypt":false,"client_email":"","ssl_cert":"","ssl_key":""})
// @Param payload.domain string true "Domain name for the proxy"
// @Param payload.ip string true "Target server IP address"
// @Param payload.port string true "Target server port"
// @Param payload.ssl bool false "Enable SSL/TLS" default(false)
// @Param payload.use_lets_encrypt bool false "Use Let's Encrypt for SSL certificate" default(false)
// @Param payload.client_email string false "Email for Let's Encrypt registration (required if use_lets_encrypt is true)"
// @Param payload.ssl_cert string false "SSL certificate content (required if ssl is true and use_lets_encrypt is false)"
// @Param payload.ssl_key string false "SSL private key content (required if ssl is true and use_lets_encrypt is false)"
// @Success 202 {string} string "Proxy configuration created"
// @Failure 400 {object} ErrorResponse "Invalid request parameters"
// @Failure 412 {object} ErrorResponse "Nginx not installed when reverse proxy is enabled"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Security NodeToken
// @Router /api/servers/{server}/proxy/create [post]
func postServerProxyCreate(c *gin.Context) {
	s := ExtractServer(c)

	// Check if reverse proxy is enabled and nginx is installed
	ok, errMsg := checkNginxRequirement()
	if !ok {
		s.Log().Error(errMsg)
		c.AbortWithStatusJSON(http.StatusPreconditionFailed, gin.H{
			"error": errMsg,
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

	// Validate Domain: must be a valid domain name (RFC style, very conservative)
	// Disallow any "/" "\" ".." or other suspicious characters
	domainRe := regexp.MustCompile(`^(?i)[a-z0-9.-]+$`)
	if !domainRe.MatchString(data.Domain) || len(data.Domain) < 1 ||
		strings.Contains(data.Domain, "/") || strings.Contains(data.Domain, "\\") || strings.Contains(data.Domain, "..") {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Invalid domain name",
		})
		return
	}
	// Validate Port: must be all digits and valid port range
	portNum, err := strconv.Atoi(data.Port)
	if err != nil || portNum < 1 || portNum > 65535 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Invalid port number",
		})
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
				log.Fatal(err)
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
// @Summary Delete server reverse proxy
// @Description Deletes an nginx reverse proxy configuration for a server. Requires nginx to be installed when reverse proxy is enabled in configuration.
// @Tags Servers
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body object true "Proxy deletion request" example({"domain":"example.com","port":"25565"})
// @Param payload.domain string true "Domain name of the proxy to delete"
// @Param payload.port string true "Port of the proxy to delete"
// @Success 202 {string} string "Proxy configuration deleted"
// @Failure 400 {object} ErrorResponse "Invalid request parameters"
// @Failure 412 {object} ErrorResponse "Nginx not installed when reverse proxy is enabled"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Security NodeToken
// @Router /api/servers/{server}/proxy/delete [delete]
func postServerProxyDelete(c *gin.Context) {
	s := ExtractServer(c)

	// Check if reverse proxy is enabled and nginx is installed
	ok, errMsg := checkNginxRequirement()
	if !ok {
		s.Log().Error(errMsg)
		c.AbortWithStatusJSON(http.StatusPreconditionFailed, gin.H{
			"error": errMsg,
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

	cmd := exec.Command("systemctl", "reload", "nginx")
	cmd.Run()

	c.Status(http.StatusAccepted)
}
