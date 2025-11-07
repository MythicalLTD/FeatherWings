package router

//go:generate sh -c "cd .. && swag init --generalInfo router/docs.go --output docs/swagger --parseDependency --parseInternal --quiet"

// @title FeatherWings API
// @version 1.0
// @description API documentation for the FeatherWings daemon.
// @BasePath /
// @schemes https http
// @securityDefinitions.apikey NodeToken
// @description Supply the node's bearer token from `config.yml` using the `Authorization: Bearer <token>` header.
// @in header
// @name Authorization
// @securityDefinitions.apikey ServerJWT
// @description Signed JWTs issued by the Panel for server-scoped operations (uploads, downloads, websockets). Pass in the `token` query parameter.
// @in query
// @name token
// @contact.name Mythical Ltd
// @contact.url https://github.com/mythicalltd/featherwings
// @produce json
// @produce text/plain
type docStub struct{}
