# Security model

DNSLeaf is a network service. Its safe defaults assume a private LAN, not an Internet-facing open resolver.

- Keep `lan_only` enabled or configure a complete IP/CIDR whitelist.
- Keep the administration panel on loopback or behind authenticated HTTPS and a firewall.
- Treat `config.json`, `stats.json`, `gravity/`, and `certs/` as secrets-bearing deployment state.
- Rotate administrator passwords and certificates if these files are copied, backed up, or exposed.
- Enable the optional HTTP/SOCKS proxy listeners only when their bind addresses and client policy are deliberate.
- Prefer trusted CA-issued certificates for remote administration. Self-signed certificates require separate trust installation on clients.
- Do not use browser password persistence for administrator credentials on shared systems.

DNS blocking is policy enforcement, not a guarantee that applications cannot use another resolver, encrypted tunnel, cached answer, or a direct IP address. Block browser DoH canaries and enforce outbound DNS policy at the network boundary when bypass resistance matters.
