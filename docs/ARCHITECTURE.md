# Architecture

DNSLeaf is a single-process DNS resolver and administration service. The same process owns DNS listeners, the web panel, optional encrypted DNS listeners, policy evaluation, query logging, and persisted configuration.

## Request flow

Every DNS request follows this order:

1. Validate that the message contains exactly one question.
2. Resolve the built-in portal hostname.
3. Apply resolver-disabled pass-through mode.
4. Apply rate limiting and client access policy.
5. Apply safe-search, override, and troll policies where configured.
6. Apply domain and profile block/allow rules.
7. Resolve local records.
8. Read the response cache and age returned TTLs.
9. Read a request-sensitive response cache and forward a miss to an enabled upstream over UDP, retrying truncated responses over TCP.
10. Inspect returned addresses for blocked IPs.
11. Record statistics, query history, and client state.

UDP and TCP DNS use the miekg/dns server. DNS-over-HTTPS enters through `/dns-query` and feeds the same resolver path. DNS-over-TLS uses the configured certificate and the same DNS handler. Optional HTTP and SOCKS proxy listeners are independent transports that reuse client access policy.

## State ownership

The configuration file is the source of truth for users, records, policies, listeners, and upstreams. Query statistics, recent query history, and client counters are persisted separately in `stats.json`. Remote blocklist data is cached under `gravity/`.

All configured relative paths are resolved from the selected configuration file directory. Runtime writes are serialized, debounced for high-frequency query state, and written through temporary files before replacement. HTTP configuration mutations are validated and committed as a single buffered request transaction. Deployment state is intentionally excluded from the public source tree.

## Concurrency boundaries

Configuration reads and mutations use a read/write lock. Query statistics, logs, clients, sessions, policy indexes, cache entries, upstream health, gravity progress, and login throttling each have their own synchronization boundary. A single background persistence worker coalesces state-save requests and performs a final flush during shutdown.

HTTP servers have bounded header, read, write, and idle timeouts. The panel exposes liveness/readiness checks, applies browser security headers, and requires an explicit marker on state-changing requests. Shutdown closes registered DNS/HTTP servers and proxy listeners, waits up to the graceful-shutdown window, stops the console, and flushes state.

## Policy boundaries

The LAN-only default prevents non-private clients from using the resolver. Whitelist-only mode replaces that decision with explicit IP/CIDR matching. The web panel and optional proxy listeners must be bound and firewalled separately from the DNS listener.

The project is intentionally local-first: it can load a local blocklist and answer local records without external services, while remote blocklists and upstream forwarding remain optional.
