# DNSLeaf

DNSLeaf is a self-hosted DNS resolver and network policy manager designed as a public, local-first alternative to Pi-hole. It combines DNS forwarding, local records, subscribed blocklists, per-client policy, query visibility, and an authenticated administration panel in one small Go service.

## Features

- UDP and TCP DNS service with upstream forwarding and response caching
- DNS-over-HTTPS and optional DNS-over-TLS listeners
- Local `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `SRV`, and `PTR` records
- Local and remote blocklists with exact, wildcard, regex, allow, and blocked-answer-IP rules
- Client naming, LAN/whitelist access controls, client profiles, scheduled policies, and conditional forwarding
- Query history, counters, client activity, upstream health, and a terminal console
- Authenticated web administration with viewer/admin roles
- Optional self-signed certificate generation for local deployments

DNSLeaf is intentionally extensible beyond a basic DNS sinkhole. It is still an actively developed project; review the security model and test your deployment before putting it on a public network.

## Quick start

Requirements: Go 1.26 or newer for development. A release binary can run without Go installed.

```powershell
Copy-Item config.example.json config.json
go build -mod=vendor -o dnsleaf.exe .
.\dnsleaf.exe --config config.json
```

Linux:

```bash
cp config.example.json config.json
go build -mod=vendor -o dnsleaf .
./dnsleaf --config config.json --no-tui
```

The first start creates an administrator and prints a generated password. Save it immediately. The default panel binds to `127.0.0.1:8080`; DNS binds to port 53 and is restricted to private clients by default.

## Configuration and operations

Runtime configuration is intentionally not tracked. Start from [`config.example.json`](config.example.json), then read:

- [Configuration](docs/CONFIGURATION.md)
- [Operations](docs/OPERATIONS.md)
- [Security model](docs/SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md)

Runtime files include `config.json`, `stats.json`, the `gravity/` blocklist cache, and generated certificates under `certs/`. These files can contain credentials, local network information, query history, or private keys and are ignored by Git.

## Administration

The web panel is available at the configured HTTP or HTTPS address. The offline console supports user, blocklist, upstream, whitelist, reload, and status commands:

```text
help
status
clients
blocklists
reload
users
whitelist
upstreams
settings
quit
```

For remote administration, use HTTPS or an SSH tunnel. Do not expose the panel, DoH endpoint, or optional proxy listeners without an explicit firewall and client-access policy.

## Development

The repository includes vendored dependencies for offline builds. Validate changes with:

```bash
go test -mod=vendor ./...
go test -race -mod=vendor ./...
go vet -mod=vendor ./...
```

The repository has no parent-directory module dependencies. `vendor/` is generated from `go.mod`; verify both vendor-mode and module-mode builds when changing dependencies.

## Project direction

The next major capabilities are long-term query storage and reporting, subscribed allowlists, richer client/list/domain group composition, DHCP server mode, diagnostic bundles, and backup/export tooling. These should be added behind tested persistence and policy boundaries rather than as independent UI-only features.
