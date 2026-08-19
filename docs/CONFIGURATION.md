# Configuration

Copy `config.example.json` to `config.json` and edit it for the deployment. `config.json` is ignored by Git because it contains password hashes, private paths, users, and local network information.

Start with:

```powershell
Copy-Item config.example.json config.json
.\dnsleaf.exe --config config.json
```

On Linux:

```bash
cp config.example.json config.json
./dnsleaf --config config.json --no-tui
```

Relative paths are resolved from the configuration file directory. Use absolute paths only when the deployment requires them.

## Important settings

- `listen`: UDP/TCP DNS bind address. `:53` serves all interfaces; use the firewall and `lan_only` together.
- `http`: administration panel bind address. Keep it on loopback unless it is intentionally protected by a trusted network or reverse proxy.
- `https`, `tls_cert_file`, `tls_key_file`: optional HTTPS panel and DoH listener.
- `upstreams`: DNS servers used for forwarding.
- `blocklists`: local paths or HTTPS URLs for subscribed domain lists.
- `lan_only`: reject clients that are not private, loopback, or link-local addresses.
- `whitelist_only`: allow only the IPs and CIDRs in `whitelist`.
- `auth`: web authentication. An empty user list creates one administrator and prints a generated password on first start.

## Runtime state

DNSLeaf writes `stats.json` and the `gravity/` cache next to the configuration file. Back up `config.json` and `stats.json` together when preserving a deployment. Do not copy private keys into source control or share a backup without protecting it.
