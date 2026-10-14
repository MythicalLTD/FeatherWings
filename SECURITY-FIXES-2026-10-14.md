# Security fixes — FeatherWings (branch `security-fixes-2026-10-14`)

Base commit: `b2c99ef` (upstream `main`). 5 files changed (incl. two new test files),
no new dependencies, no new configuration. The panel protocol is unchanged: the panel still
calls `POST /api/servers/{uuid}/proxy/create` with `{domain, ip, port, ssl, …}`.

## FW-1 — nginx configuration and path injection via proxy fields

`router/router_server_proxy.go` concatenated the request fields `domain`, `ip` and `port`
straight into the generated nginx configuration:

```
server_name <domain>;
proxy_pass http://<ip>:<port>;
```

and used `<domain>` in filesystem paths
(`/etc/nginx/sites-available/<domain>_<port>.conf`, `/srv/server_certs/<domain>`, plus
`os.RemoveAll` on delete). A newline/semicolon in the domain would have injected arbitrary
nginx directives (written and reloaded as root), and `..` segments would have escaped the
`/etc/nginx` and `/srv/server_certs` directories; the same value was used as a filename.

FeatherPanel validates the domain before sending it, so this was not reachable through the
panel — but the daemon must not rely on its caller (other panels, other versions, or a
compromised panel turn this into root code execution).

Fix (applies to the create path with and without SSL, and to the delete path):

* `validateProxyDomain()`: RFC-1123 hostname, max 253 characters, labels 1–63, no leading/
  trailing dot, no `..`.
* `validateProxyIP()`: `net.ParseIP` (IPv4/IPv6).
* `validateProxyPort()`: numeric, 1–65535.
* Invalid values → HTTP 400 **before** anything is written or deleted.
* `safeProxySlug()` builds the config file name; for values accepted by the validator it is
  the identity, so existing config files keep being found and removed.
* IPv6 literals are bracketed in `proxy_pass` (`[::1]:25565`) instead of producing broken
  configuration.

## FW-2 — SSH host key verification during server import

`server/import.go` used `ssh.InsecureIgnoreHostKey()` with password authentication, so
anyone on the network path could feed content into a customer volume.

Fix: `importHostKeyCallback()` verifies against `~/.ssh/known_hosts` when the host is known
(a key mismatch now aborts the import). For hosts that are not listed — the panel does not
send a fingerprint today — the connection behaves as before, but logs a clear
`insecure host key: <host> not in known_hosts` warning. No new configuration required.

## FW-3 — Unbounded archive extraction

`system/nodebackup/nodebackup.go` extracted tar entries with an unlimited `io.Copy`, so a
prepared backup could fill the node's disk.

Fix: `maxRestoreTotalBytes` (50 GiB) is checked against each entry header and tracked while
extracting; exceeding it aborts with an error. Normal backups are unaffected.

## Verification

* `go build ./...` → exit 0.
* `go vet ./...` → identical to the baseline (no new warnings).
* `go test ./router/... ./system/nodebackup/...` → all green, including the new
  `router/router_server_proxy_test.go` (valid/invalid domains, IPs, ports, slug) and
  `system/nodebackup/nodebackup_test.go` (oversized archive rejected, normal archive
  accepted). Manual check output: `example.com`, `sub.example.com`, `a.b.c.d`, `127.0.0.1`,
  `::1`, port `25565` accepted; `"example.com\n"`, `..`, `../etc/nginx`, `a/b`,
  `not-an-ip`, `999.1.1.1`, ports `0`/`65536`/`80abc` rejected; `safeProxySlug("../etc/nginx")`
  → `__etc_nginx`.
* `gofmt -l` shows one pre-existing finding fewer (the repository keeps CRLF files; the
  branch adds no new formatting findings).
* The patch applies cleanly on a fresh clone of `b2c99ef` (`git apply --check --3way`,
  5 files).

## Intentionally not changed

* **SHA-1 for backup ids** (`server/backup/backup.go`, `backup_pbs.go`,
  `system/nodebackup/nodebackup.go`): the checksums are reported to the panel with
  `checksum_type=sha1` and persisted in `*.meta.json`; SHA-256 would invalidate existing
  backups and the panel-side verification. Known and accepted (no integrity attack surface
  without a matching oracle).
* **pprof and the autocert HTTP listener** (`cmd/root.go`): pprof binds to `localhost` only;
  the plain HTTP listener on `:80` is the ACME HTTP-01 challenge server and is restricted by
  a host whitelist. Audited, no change.
