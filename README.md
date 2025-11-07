# FeatherWings

Wings is featherpanel's server control plane, built for the rapidly changing gaming industry and designed to be
highly performant and secure. Wings provides an HTTP API allowing you to interface directly with running server
instances, fetch server logs, generate backups, and control all aspects of the server lifecycle.

In addition, Wings ships with a built-in SFTP server allowing your system to remain free of FeatherPanel specific
dependencies, and allowing users to authenticate with the same credentials they would normally use to access the Panel.

## API Documentation

Swagger/OpenAPI documentation is generated from inline annotations under `router/`.

```
go generate ./router
```

The daemon serves the generated spec at `/api/docs/openapi.json`, and provides an interactive Swagger UI at `/api/docs/ui` whenever `api.docs.enabled` is `true` in `config.yml`.

## Reporting Issues

Feel free to report any wings specific issues or feature requests in [GitHub Issues](https://github.com/mythicalltd/featherwings/issues/new).
