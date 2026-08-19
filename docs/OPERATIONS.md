# Operations

## First start

1. Copy `config.example.json` to `config.json`.
2. Review the DNS and panel bind addresses. Keep `lan_only` enabled unless every client is explicitly controlled.
3. Start DNSLeaf and save the generated administrator password.
4. Open the panel at the configured loopback address.
5. Create and trust a CA-issued certificate before enabling HTTPS for remote administration.

The `--no-tui` mode is suitable for a service. A normal stop signal closes DNS, HTTP, HTTPS, DoT, and proxy listeners and flushes pending query state before returning.

## Health checks

Use a DNS client against both transports:

```bash
dig @127.0.0.1 example.com
dig +tcp @127.0.0.1 example.com
```

If DoH is enabled, send `application/dns-message` requests to `/dns-query`. The unauthenticated panel health endpoint is intended for local checks only:

```bash
curl http://127.0.0.1:8080/api/ping
```

For service monitoring, use the unauthenticated liveness and readiness endpoints:

```bash
curl http://127.0.0.1:8080/api/healthz
curl -i http://127.0.0.1:8080/api/readyz
```

`healthz` reports that the process is alive. `readyz` returns `503` until the DNS serving loops have started, the panel listeners are bound, and an active upstream is available, unless forwarding is disabled. Startup bind and TLS failures are returned to the service manager.

Authenticated monitoring and maintenance endpoints are available at `/metrics`, `/api/audit`, and `/api/backup`. Treat backup archives as secrets because they contain the configuration and password hashes.

## Blocklists and policy changes

Use the panel's Gravity action or the console's `gravity` command to refresh blocklists. Local sources are resolved relative to the configuration file. Remote sources use a bounded request timeout, reject downloads over 50 MiB, refresh stale caches after 24 hours, and retain a cached copy if refresh fails.

After changing records, policies, users, or listeners, confirm the success response and restart DNSLeaf when a listener address or certificate changes. Listener settings are read at startup; configuration writes do not reopen existing sockets.

## Backups and updates

Back up `config.json`, `stats.json`, local blocklists, and certificate material separately. Do not overwrite a live configuration while DNSLeaf is running. Stop the service, copy the files, replace the binary, then start it again and verify both UDP and TCP DNS.

After source updates, run:

```bash
go mod verify
go test -mod=vendor ./...
go test -race -mod=vendor ./...
go test -mod=mod ./...
go vet -mod=vendor ./...
```

Validate a configuration without opening listeners:

```bash
./dnsleaf --config config.json validate
```

The vendored build is the reproducible offline build. Regenerate it with `go mod vendor` after dependency changes, then verify both vendor and module test runs before publishing a release.

## Linux service

Run DNSLeaf under a dedicated unprivileged service account with `CAP_NET_BIND_SERVICE`, a private configuration directory, and a firewall that permits DNS only from intended clients. The service installer derives `WorkingDirectory`, `ExecStart`, and `--config` from the selected executable and configuration; it writes the unit to the standard systemd unit directory.
