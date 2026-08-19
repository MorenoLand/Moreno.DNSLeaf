# Security model

DNSLeaf is a network service. Its safe defaults assume a private LAN, not an Internet-facing open resolver.

- Keep `lan_only` enabled or configure a complete IP/CIDR whitelist.
- Keep the administration panel on loopback or behind authenticated HTTPS and a firewall.
- Treat `config.json`, `stats.json`, `gravity/`, and `certs/` as deployment state that may contain credentials, query history, or private keys.
- Passwords are stored as salted PBKDF2-SHA-256 hashes. Failed logins are throttled, session cookies are HttpOnly/SameSite, and password or role changes revoke affected sessions.
- State-changing web API requests require the `X-DNSLeaf-Request: 1` header. The bundled UI and remote console add it automatically; custom API clients must send it themselves. This reduces browser cross-site request risk but does not replace authentication or HTTPS.
- Do not use browser password persistence for administrator credentials on shared systems.
- Prefer trusted CA-issued certificates for remote administration. Self-signed certificates require separate trust installation on clients.
- Enable the optional HTTP/SOCKS proxy listeners only when their bind addresses and client policy are deliberate; an intentionally enabled proxy can reach destinations on behalf of allowed clients.
- Do not expose unauthenticated `/api/ping`, DoH, or DNS listeners to networks that are not part of the deployment policy.

The web service applies request header, body, and server timeout limits plus `nosniff`, frame-denial, referrer, permissions, CSP, and HTTPS HSTS response headers. DNS forwarding uses bounded UDP/TCP exchange timeouts, retries truncated UDP responses over TCP, and returns a server-failure response when all configured upstreams fail.

DNS blocking is policy enforcement, not a guarantee that applications cannot use another resolver, encrypted tunnel, cached answer, or a direct IP address. Block browser DoH canaries and enforce outbound DNS policy at the network boundary when bypass resistance matters.
