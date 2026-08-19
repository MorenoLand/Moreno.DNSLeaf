# Configuration

Copy `config.example.json` to `config.json` and edit it for the deployment. `config.json` is ignored by Git because it contains password hashes, users, local network information, and deployment paths.

```powershell
Copy-Item config.example.json config.json
.\dnsleaf.exe --config config.json
```

```bash
cp config.example.json config.json
./dnsleaf --config config.json --no-tui
```

Relative paths are resolved from the configuration file directory, so the configuration and binary can be moved together without changing runtime paths. Absolute paths remain supported when a deployment needs them.

## Command-line modes

- `--config path` selects the configuration file. A positional path is also accepted.
- `--no-tui` runs without the terminal console and is intended for services and containers.
- `validate` checks the selected configuration and schema without starting listeners.
- `user list|add|reset|role|remove` manages web users without starting listeners.
- `service install|uninstall` manages the Linux systemd unit using the selected executable and configuration paths.

`schema_version` is written by DNSLeaf and is currently `1`. Configurations from schema `0` are upgraded in memory; a newer schema is rejected rather than silently rewritten.

## Listeners and forwarding

- `listen` is the UDP and TCP DNS bind address. `:53` serves all interfaces; bind a specific address when the resolver should be local to one interface.
- `http` is the administration panel bind address. Keep it on loopback unless remote access is intentional.
- `https` enables the HTTPS panel and DoH endpoint when `tls_cert_file` and `tls_key_file` are also set.
- `dot` enables DNS-over-TLS when the same certificate and key are available.
- `upstreams` contains DNS server addresses. Truncated UDP responses are retried over TCP.
- `conditional_forwarding` selects alternate upstreams for matching domain suffixes.
- `upstream_health` probes configured upstreams and temporarily excludes repeatedly failing servers.

## Policy and records

- `records` contains local `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `SRV`, and `PTR` answers.
- `blocked`, `allowed`, and `blocked_ips` provide manual policy rules. `blocklists` adds local files or HTTPS subscriptions; remote data is cached under `gravity/`.
- `profiles` and `client_profiles` apply per-client policy. `scheduled_rules` can change policy during defined windows.
- `lan_only` rejects non-private, non-loopback, and non-link-local clients unless they are explicitly whitelisted.
- `whitelist_only` accepts only clients matching `whitelist`.
- `rate_limit` limits query volume per client. `anomaly` records repeated blocked-domain hits in the server log.

## Cache and runtime state

`cache_enabled`, `cache_size`, and `cache_ttl_seconds` control response caching. The configured TTL caps authoritative positive or negative TTLs; responses without a useful TTL are not cached. Cached responses are returned with TTLs reduced by their age.

DNSLeaf writes `stats.json` and the `gravity/` cache beside the configuration file. Configuration and state updates use temporary files and replacement writes, and state files are created with private permissions where the platform supports them. Back up `config.json`, `stats.json`, blocklists, and certificate material separately.

## Authentication and optional proxies

Set `auth.enabled` to true for the web panel. An empty user list causes DNSLeaf to create one administrator and print a generated password on first start. Password changes, role changes, and removals revoke the affected sessions. Login failures are throttled per client address.

`http_proxy_enabled`/`http_proxy` and `socks_proxy_enabled`/`socks_proxy` enable optional outbound proxy listeners. These are separate listeners with the same client access policy as DNS and should remain disabled unless their bind addresses and firewall rules are deliberate.
