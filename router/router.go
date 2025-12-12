package router

import (
	"context"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/gin-gonic/gin"
	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/environment/docker"
	"github.com/mythicalltd/featherwings/modules"
	"github.com/mythicalltd/featherwings/modules/alwaysmotd"
	"github.com/mythicalltd/featherwings/remote"
	"github.com/mythicalltd/featherwings/router/middleware"
	wserver "github.com/mythicalltd/featherwings/server"
)

// Configure configures the routing infrastructure for this daemon instance.
func Configure(m *wserver.Manager, client remote.Client) *gin.Engine {
	gin.SetMode("release")

	router := gin.New()
	router.Use(gin.Recovery())
	if err := router.SetTrustedProxies(config.Get().Api.TrustedProxies); err != nil {
		panic(errors.WithStack(err))
	}
	router.Use(middleware.AttachRequestID(), middleware.CaptureErrors(), middleware.SetAccessControlHeaders())
	router.Use(middleware.AttachServerManager(m), middleware.AttachApiClient(client))

	// Initialize module manager and register modules
	moduleManager := initializeModules(m)

	// Restore enabled modules from database
	ctx := context.Background()
	if err := moduleManager.RestoreModules(ctx, m); err != nil {
		log.WithError(err).Error("failed to restore modules from database")
	}

	router.Use(middleware.AttachModuleManager(moduleManager))
	// @todo log this into a different file so you can setup IP blocking for abusive requests and such.
	// This should still dump requests in debug mode since it does help with understanding the request
	// lifecycle and quickly seeing what was called leading to the logs. However, it isn't feasible to mix
	// this output in production and still get meaningful logs from it since they'll likely just be a huge
	// spamfest.
	router.Use(gin.LoggerWithFormatter(func(params gin.LogFormatterParams) string {
		log.WithFields(log.Fields{
			"client_ip":  params.ClientIP,
			"status":     params.StatusCode,
			"latency":    params.Latency,
			"request_id": params.Keys["request_id"],
		}).Debugf("%s %s", params.MethodColor()+params.Method+params.ResetColor(), params.Path)

		return ""
	}))

	// Public documentation endpoints
	if config.Get().Api.Docs.Enabled {
		registerDocumentationRoutes(router)
	}

	// These routes use signed URLs to validate access to the resource being requested.
	router.GET("/download/backup", getDownloadBackup)
	router.GET("/download/file", getDownloadFile)
	router.POST("/upload/file", postServerUploadFiles)

	// This route is special it sits above all the other requests because we are
	// using a JWT to authorize access to it, therefore it needs to be publicly
	// accessible.
	router.GET("/api/servers/:server/ws", middleware.ServerExists(), getServerWebsocket)

	// This request is called by another daemon when a server is going to be transferred out.
	// This request does not need the AuthorizationMiddleware as the panel should never call it
	// and requests are authenticated through a JWT the panel issues to the other daemon.
	router.POST("/api/transfers", postTransfers)

	// All the routes beyond this mount will use an authorization middleware
	// and will not be accessible without the correct Authorization header provided.
	protected := router.Group("")
	protected.Use(middleware.RequireAuthorization())
	protected.POST("/api/update", postUpdateConfiguration)
	protected.GET("/api/system", getSystemInformation)
	protected.POST("/api/system/self-update", postSystemSelfUpdate)
	protected.GET("/api/diagnostics", getDiagnostics)
	protected.GET("/api/system/docker/disk", getDockerDiskUsage)
	protected.DELETE("/api/system/docker/image/prune", pruneDockerImages)
	protected.GET("/api/system/ips", getSystemIps)
	protected.GET("/api/system/utilization", getSystemUtilization)
	protected.POST("/api/system/terminal/exec", postSystemHostCommand)

	// Configuration management routes (new, preserves comments)
	protected.GET("/api/config", getConfigRaw)
	protected.PUT("/api/config", putConfigRaw)
	protected.PATCH("/api/config/patch", patchConfig)
	protected.GET("/api/config/schema", getConfigSchema)

	protected.GET("/api/servers", getAllServers)
	protected.POST("/api/servers", postCreateServer)
	protected.DELETE("/api/transfers/:server", deleteTransfer)

	// Module management routes
	protected.GET("/api/modules", getModules)
	module := protected.Group("/api/modules/:module")
	{
		module.GET("/config", getModuleConfig)
		module.PUT("/config", putModuleConfig)
		module.POST("/enable", postModuleEnable)
		module.POST("/disable", postModuleDisable)
	}

	// These are server specific routes, and require that the request be authorized, and
	// that the server exist on the Daemon.
	server := router.Group("/api/servers/:server")
	server.Use(middleware.RequireAuthorization(), middleware.ServerExists())
	{
		server.GET("", getServer)
		server.DELETE("", deleteServer)

		server.GET("/logs", getServerLogs)
		server.GET("/install-logs", getServerInstallLogs)
		server.POST("/power", postServerPower)
		server.POST("/commands", postServerCommands)
		server.POST("/install", postServerInstall)
		server.POST("/reinstall", postServerReinstall)
		server.POST("/sync", postServerSync)
		server.POST("/ws/deny", postServerDenyWSTokens)

		// This archive request causes the archive to start being created
		// this should only be triggered by the panel.
		server.POST("/transfer", postServerTransfer)
		server.DELETE("/transfer", deleteServerTransfer)

		// Reverse proxy routes
		server.POST("/proxy/create", postServerProxyCreate)
		server.POST("/proxy/delete", postServerProxyDelete)

		// Server import routes
		server.POST("/import", postServerImport)


		// Deletes all backups for a server
		server.DELETE("deleteAllBackups", deleteAllServerBackups)

		files := server.Group("/files")
		{
			files.GET("/contents", getServerFileContents)
			files.GET("/list-directory", getServerListDirectory)
			files.PUT("/rename", putServerRenameFiles)
			files.POST("/copy", postServerCopyFile)
			files.POST("/write", postServerWriteFile)
			files.POST("/create-directory", postServerCreateDirectory)
			files.POST("/delete", postServerDeleteFiles)
			files.POST("/compress", postServerCompressFiles)
			files.POST("/decompress", postServerDecompressFiles)
			files.POST("/chmod", postServerChmodFile)
			files.GET("/search", getFilesBySearch)

			files.GET("/pull", middleware.RemoteDownloadEnabled(), getServerPullingFiles)
			files.POST("/pull", middleware.RemoteDownloadEnabled(), postServerPullRemoteFile)
			files.DELETE("/pull/:download", middleware.RemoteDownloadEnabled(), deleteServerPullRemoteFile)
		}

		backup := server.Group("/backup")
		{
			backup.GET("", getServerBackups)
			backup.POST("", postServerBackup)
			backup.POST("/:backup/restore", postServerRestoreBackup)
			backup.DELETE("/:backup", deleteServerBackup)
		}

		firewallGroup := server.Group("/firewall")
		{
			firewallGroup.GET("", getFirewallRules)
			firewallGroup.POST("", postFirewallRule)
			firewallGroup.POST("/sync", postSyncFirewallRules)
			firewallGroup.GET("/port/:port", getFirewallRulesByPort)
			firewallGroup.GET("/:rule", getFirewallRule)
			firewallGroup.PUT("/:rule", putFirewallRule)
			firewallGroup.DELETE("/:rule", deleteFirewallRule)
		}
	}

	return router
}

// initializeModules creates and registers all available modules
func initializeModules(serverManager *wserver.Manager) *modules.Manager {
	moduleManager := modules.NewManager()

	// Register AlwaysMOTD module
	alwaysMotd := alwaysmotd.New()
	if err := moduleManager.Register(alwaysMotd); err != nil {
		log.WithError(err).Fatal("failed to register AlwaysMOTD module")
	}

	// Set up port unbinder registry to allow AlwaysMOTD to register itself
	// This breaks the import cycle by using a callback pattern
	alwaysmotd.SetPortUnbinderRegistry(func(unbinder alwaysmotd.PortUnbinderFunc) {
		docker.RegisterPortUnbinder(docker.PortUnbinderFunc(unbinder))
	})

	log.Info("modules initialized")
	return moduleManager
}
