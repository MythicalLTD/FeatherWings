package router

import (
	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/server"
)

// ExtractServer returns the server instance from the gin context. If there is
// no server set in the context (e.g. calling from a controller not protected
// by ServerExists) this function will panic.
//
// This function is deprecated. Use middleware.ExtractServer.
func ExtractServer(c *gin.Context) *server.Server {
	return middleware.ExtractServer(c)
}
