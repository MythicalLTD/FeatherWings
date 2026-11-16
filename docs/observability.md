# Observability: health checks and Prometheus metrics

Wings has liveness and readiness probes and an optional Prometheus `/metrics`
endpoint. The repository includes an example Prometheus config, alert rules
and a Grafana dashboard:

- `contrib/prometheus/prometheus.yml`: scrape config
- `contrib/prometheus/featherwings-alerts.yml`: alert rules
- `contrib/grafana/featherwings.json`: Grafana dashboard (Dashboards → Import)

## Health checks

| Endpoint | Auth | Answer |
|---|---|---|
| `GET /health/live` | none | `200 {"status":"ok"}` while Wings serves requests |
| `GET /health/ready` | none (details need auth) | `200` when every critical check passes, `503` otherwise |

Both are served on the main API listener and, if configured, on the dedicated
metrics listener.

Readiness checks:

| Check | Critical | Passes when |
|---|---|---|
| `docker` | yes | the Docker daemon answers a ping |
| `data_directory` | yes | a file can be created in `system.data` |
| `disk_space` | yes | `system.data` has at least `health.min_free_disk_mb` MiB free |
| `sftp` | yes | the SFTP server is accepting connections |
| `panel` | no | the Panel answered a request in the last `health.panel_contact_max_age` seconds, or answers a probe (cached for 30 s) |

`status` is `ok`, `degraded` (only a non-critical check failed, still `200`) or
`unavailable` (`503`).

Callers without credentials only get the status of each check. The messages
and timings are shown to requests with the node token
(`Authorization: Bearer <node token>`), to requests that may read `/metrics`,
and to anyone on a loopback-only metrics listener.

```json
{
  "status": "ok",
  "checks": {
    "data_directory": {"status": "ok", "critical": true, "message": "data directory is writable"},
    "disk_space": {"status": "ok", "critical": true, "message": "65661 MiB free, 1024 MiB required"},
    "docker": {"status": "ok", "critical": true, "message": "docker daemon is reachable", "duration_ms": 2},
    "panel": {"status": "ok", "critical": false, "message": "last panel response 12s ago"},
    "sftp": {"status": "ok", "critical": true, "message": "sftp server is accepting connections"}
  }
}
```

## Prometheus metrics

Off by default. Configure it in `config.yml`:

```yaml
metrics:
  enabled: true
  # Dedicated listener. When port is 0, /metrics is served on the main API
  # listener instead, and a token or allowed_ips is required there.
  host: 127.0.0.1
  port: 9101
  # Optional. Sent by Prometheus as "Authorization: Bearer <token>".
  token: "change-me-to-a-long-random-string"
  # Optional. IP addresses or CIDR ranges allowed to scrape.
  allowed_ips:
    - 10.0.0.0/8
  # Export per-server metrics labelled by server UUID.
  per_server: true

health:
  min_free_disk_mb: 1024
  panel_contact_max_age: 300
```

### Protection

`/metrics` is never served unprotected on a public address:

- **Dedicated listener on loopback** (`host: 127.0.0.1`, `localhost`, `::1`):
  served without auth, for a Prometheus or agent on the same machine.
- **Dedicated listener on any other address:** Wings refuses to start the
  listener unless `token` or `allowed_ips` is set.
- **Main API listener** (`port: 0`): `/metrics` answers `404` unless `token`
  or `allowed_ips` is set. The client IP respects `api.trusted_proxies`.
- When both `token` and `allowed_ips` are set, a request must pass both. A
  wrong or missing token gets `401`, and an IP outside the list gets `403`.
- The node token does **not** grant access to `/metrics`. Use a separate
  read-only token.

### Exported metrics

| Metric | Type | Labels |
|---|---|---|
| `go_*`, `process_*` | Go runtime and process metrics | |
| `featherwings_http_requests_total` | counter | `method`, `route`, `status` |
| `featherwings_http_request_duration_seconds` | histogram | `method`, `route` |
| `featherwings_http_requests_in_flight` | gauge | |
| `featherwings_servers` | gauge | `state` (offline, starting, running, stopping) |
| `featherwings_server_state` | gauge (1 for the current state) | `server`, `state` |
| `featherwings_server_cpu_absolute_percent` | gauge | `server` |
| `featherwings_server_memory_bytes` | gauge | `server` |
| `featherwings_server_memory_limit_bytes` | gauge | `server` |
| `featherwings_server_disk_bytes` | gauge | `server` |
| `featherwings_server_network_rx_bytes_total` | counter (resets when the container restarts) | `server` |
| `featherwings_server_network_tx_bytes_total` | counter (resets when the container restarts) | `server` |
| `featherwings_server_uptime_seconds` | gauge | `server` |
| `featherwings_backups_in_progress` | gauge | |
| `featherwings_backups_total` | counter | `result` (success, failure) |
| `featherwings_transfers_in_progress` | gauge | `direction` (incoming, outgoing) |
| `featherwings_transfers_total` | counter | `direction`, `result` |
| `featherwings_sftp_sessions` | gauge | |
| `featherwings_sftp_listening` | gauge | |
| `featherwings_websocket_connections` | gauge | |
| `featherwings_docker_up` | gauge | |
| `featherwings_panel_requests_total` | counter | `result` (success, client_error, server_error, network_error) |
| `featherwings_panel_last_contact_timestamp_seconds` | gauge | |

`route` is the route template (for example `/api/servers/:server/files/contents`),
so server UUIDs and file paths never become label values. Per-server metrics
come from the same resource tracking the Panel uses, so scraping adds no extra
Docker stats calls. Set `per_server: false` on nodes with very many servers if
the label count matters.

### Prometheus and Grafana

1. Enable metrics as above and restart Wings.
2. Add a job from `contrib/prometheus/prometheus.yml` and, optionally, the
   rules in `contrib/prometheus/featherwings-alerts.yml`.
3. In Grafana, import `contrib/grafana/featherwings.json` and pick your
   Prometheus data source. The dashboard has `job`, `instance` and `server`
   filters.

Quick check from the node:

```sh
curl -s http://127.0.0.1:9101/health/ready | jq
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9101/metrics | grep ^featherwings_
```
