# Contributing

Contributions should preserve DNS correctness, safe deployment defaults, and platform-neutral paths.

Before opening a change, run:

```bash
go test -mod=vendor ./...
go test -race -mod=vendor ./...
go vet -mod=vendor ./...
go mod verify
```

Changes that affect configuration, persistence, policy precedence, DNS forwarding, or authentication should include regression coverage and update the relevant file under `docs/`. Do not commit runtime state, credentials, generated certificates, binaries, or local blocklists.

The repository workflow is manual-only. Maintainers decide when checks and release builds run.
