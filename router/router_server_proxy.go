// This file is part of the Pterodactyl Server Reverse Proxy Blueprint Addon.
// All rights to this code belong to its owner Jelco.
// Product page: https://www.sourcexchange.net/teams/2/profile
// Source: https://blueprint.zip/browse/reverseproxy
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

	"github.com/gin-gonic/gin"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
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

// Create a server proxy
func postServerProxyCreate(c *gin.Context) {
	s := ExtractServer(c)

	var data struct {
		Domain  string `json:"domain"`
		IP      string `json:"ip"`
		Port    string `json:"port"`
		Ssl     bool   `json:"ssl"`
		UseLetsEncrypt bool `json:"use_lets_encrypt"`
		ClientEmail string `json:"client_email"`
		SslCert string `json:"ssl_cert"`
		SslKey  string `json:"ssl_key"`
	}

	if err := c.BindJSON(&data); err != nil {
		return
	}

	// Validate Domain and Port to prevent path traversal and illegal characters
	if strings.Contains(data.Domain, "/") || strings.Contains(data.Domain, "\\") || strings.Contains(data.Domain, "..") ||
		strings.Contains(data.Port, "/") || strings.Contains(data.Port, "\\") || strings.Contains(data.Port, "..") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid domain or port"})
		return
	}
	// Optionally: stricter check for allowed domain and port format can be applied here

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

// Delete a server proxy
func postServerProxyDelete(c *gin.Context) {
	s := ExtractServer(c)

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
