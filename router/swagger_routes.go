package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	docsSwagger "github.com/mythicalltd/featherwings/docs/swagger"
)

func registerDocumentationRoutes(routes gin.IRoutes) {
	openapiPath := "/api/docs/openapi.json"
	uiPrefix := "/api/docs/ui"

	routes.GET(openapiPath, func(c *gin.Context) {
		doc := docsSwagger.SwaggerInfo.ReadDoc()
		c.Data(http.StatusOK, "application/json", []byte(doc))
	})

	routes.GET("/api/docs", func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, uiPrefix+"/index.html")
	})

	swaggerHandler := ginSwagger.WrapHandler(
		swaggerFiles.Handler,
		ginSwagger.URL(openapiPath),
		ginSwagger.DefaultModelsExpandDepth(-1),
	)
	routes.GET(uiPrefix, func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, uiPrefix+"/index.html")
	})
	routes.GET(uiPrefix+"/*any", swaggerHandler)
}
