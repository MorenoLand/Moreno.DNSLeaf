# Operations

## First start

1. Copy `config.example.json` to `config.json`.
2. Review the DNS bind address and keep `lan_only` enabled unless every client is explicitly controlled.
3. Start DNSLeaf and save the generated administrator password.
4. Open the panel at the configured loopback address.
5. Create a trusted certificate before enabling HTTPS for remote administration.

## Health checks

Use a DNS client against the configured listener:

```bash
dig @127.0.0.1 example.com
dig +tcp @127.0.0.1 example.com
```

Use the panel health endpoint locally:

```bash
curl http://127.0.0.1:8080/api/ping
```

The health endpoint does not authenticate and should not be exposed as a sensitive monitoring endpoint on an untrusted network.

## Backups and updates

Back up `config.json`, `stats.json`, local blocklists, and certificate material separately. Do not overwrite a live configuration while DNSLeaf is running. Stop the service, copy the files, replace the binary, then start it again and verify both UDP and TCP DNS.

After source updates, run:

```bash
go test -mod=vendor ./...
go vet -mod=vendor ./...
```

The vendored build is the reproducible offline build. Regenerate it with `go mod vendor` after dependency changes, then verify both `-mod=vendor` and `-mod=mod` test runs before publishing a release.
## Linux service

Run DNSLeaf under a dedicated unprivileged service account with `CAP_NET_BIND_SERVICE`, a private configuration directory, and a firewall that permits DNS only from intended clients. Do not expose the administration panel or optional proxies without an explicit access policy.
