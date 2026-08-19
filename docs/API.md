# HTTP API

The web API is served from the configured HTTP and HTTPS listeners. The bundled panel and remote console are the reference clients.

## Access and request rules

- `GET /api/healthz` is an unauthenticated process liveness check.
- `GET /api/readyz` is an unauthenticated readiness check and returns `503` until DNS and HTTP listeners are registered and at least one upstream is active, unless forwarding is disabled.
- `GET /api/ping` remains available for simple compatibility checks.
- `/dns-query` accepts DNS-over-HTTPS `GET` and `POST` messages without panel authentication; protect it with the listener bind address and firewall policy.
- When authentication is enabled, administration endpoints require the `dnsleaf_session` cookie. Viewer sessions can read data; admin sessions are required for state changes.
- Every state-changing request must include `X-DNSLeaf-Request: 1`. This is required for browser cross-site request protection and is separate from authentication.
- JSON request bodies are limited by the HTTP middleware. DNS-over-HTTPS messages are limited to 64 KiB.

## Main resources

The administration panel uses these resources:

- `/api/session` and `/api/login` for authentication state
- `/api/status`, `/api/log`, `/api/server-log`, and `/api/clients` for runtime data
- `/api/records` and `/api/records/import` for local records
- `/api/blocked`, `/api/blocked-ips`, `/api/allowed`, `/api/regex-rules`, `/api/blocklists`, and `/api/block-groups` for policy
- `/api/upstreams`, `/api/profiles`, and `/api/clients/*/profile` for routing policy
- `/api/settings` and `/api/tls/selfsigned` for configuration and certificate operations
- `/api/users` for administrator-managed accounts

Successful configuration mutations are validated and persisted atomically. If persistence fails, the request returns an error and the in-memory configuration is restored.

Listener addresses and certificate paths are read at startup. Restart DNSLeaf after changing those settings.
