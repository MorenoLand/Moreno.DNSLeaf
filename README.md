# DNSLeaf

DNSLeaf is a self-hosted DNS resolver and network policy manager designed as a public, local-first alternative to Pi-hole. It combines DNS forwarding, local records, subscribed blocklists, per-client policy, query visibility, and an authenticated administration panel in one small Go service.

## Features

- UDP and TCP DNS service with upstream forwarding and response caching
- Validated UDP, TCP, DNS-over-TLS, and DNS-over-HTTPS upstream endpoints with EDNS client-subnet stripping
- DNS-over-HTTPS and optional DNS-over-TLS listeners
- Local `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `SRV`, `PTR`, `HTTPS`, and `SVCB` records
- Local and remote blocklists with exact, wildcard, regex, allow, and blocked-answer-IP rules
- Client naming, LAN/whitelist access controls, client profiles, scheduled policies, and conditional forwarding
- Query history, counters, client activity, upstream health, and a terminal console
- Configurable query retention and client-IP anonymization, structured admin audit history, metrics, and backups
- Authenticated web administration with viewer/admin roles
- Optional self-signed certificate generation for local deployments

DNSLeaf is intentionally extensible beyond a basic DNS sinkhole. It is still an actively developed project; review the security model and test your deployment before putting it on a public network.

## Quick start

Requirements: Go 1.25.3 or newer for development. CI also verifies the current Go 1.26.x toolchain. A release binary can run without Go installed.

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

Validate a configuration without starting listeners:

```text
dnsleaf --config config.json validate
```

Print build metadata without loading a configuration:

```text
dnsleaf --version
```

The first start creates an administrator and prints a generated password. Save it immediately. The default panel binds to `127.0.0.1:8080`; DNS binds to port 53 and is restricted to private clients by default.

## Configuration and operations

Runtime configuration is intentionally not tracked. Start from [`config.example.json`](config.example.json), then read:

- [Configuration](docs/CONFIGURATION.md)
- [Operations](docs/OPERATIONS.md)
- [Security model](docs/SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md)
- [HTTP API](docs/API.md)
- [Releasing](docs/RELEASING.md)

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

Authenticated operators can query `/metrics`, `/api/audit`, and `/api/backup`. Metrics are Prometheus-compatible; audit entries record successful state-changing API requests; backups contain `config.json`, `stats.json` when present, and the cached `gravity/` blocklists. Backups include password hashes and must be protected like the source configuration.

## Development

The repository includes vendored dependencies for offline builds. Validate changes with:

```bash
go test -mod=vendor ./...
go test -race -mod=vendor ./...
go test -mod=mod ./...
go vet -mod=vendor ./...
go mod verify
```

For a local release build with embedded version metadata, use `scripts/build.ps1` on Windows or `scripts/build.sh` on Unix-like systems. These scripts write binaries under the ignored `dist/` directory and do not publish artifacts.

The repository has no parent-directory module dependencies. `vendor/` is generated from `go.mod`; verify both vendor-mode and module-mode builds when changing dependencies.

## Project direction

Future work should build on the tested configuration, persistence, policy, and transport boundaries. Candidate areas include DNSSEC validation, subscribed allowlists, richer client/list/domain group composition, DHCP server mode, and long-term reporting.

## License

DNSLeaf is released under the [MIT License](LICENSE). Vendored dependencies retain their own licenses.
