# Architecture

DNSLeaf is a single-process DNS resolver and administration service. The same process owns DNS listeners, the web panel, optional encrypted DNS listeners, policy evaluation, query logging, and persisted configuration.

## Request flow

Every DNS request follows this order:

1. Validate that the message has a question.
2. Resolve the built-in portal hostname.
3. Apply resolver-disabled pass-through mode.
4. Apply rate limiting and client access policy.
5. Apply safe-search, override, and troll policies where configured.
6. Apply domain and profile block/allow rules.
7. Resolve local records.
8. Read the response cache.
9. Forward to an enabled upstream and inspect returned addresses.
10. Record statistics, query history, and client state.

UDP and TCP DNS use the miekg/dns server. DNS-over-HTTPS enters through `/dns-query` and feeds the same resolver path. DNS-over-TLS uses the configured certificate and the same DNS handler.

## State ownership

The configuration file is the source of truth for users, records, policies, listeners, and upstreams. Query statistics, recent query history, and client counters are persisted separately in `stats.json`. Remote blocklist data is cached under `gravity/`.

All runtime files should live beside the selected configuration file. They are local deployment state and are intentionally excluded from the public source tree.

## Policy boundaries

The LAN-only default prevents non-private clients from using the resolver. Whitelist-only mode replaces that decision with explicit IP/CIDR matching. The web panel and optional proxy listeners must be bound and firewalled separately from the DNS listener.

The project is intentionally local-first: it can load a local blocklist and answer local records without external services, while remote blocklists and upstream forwarding remain optional.
