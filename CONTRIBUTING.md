# Contributing

Contributions should preserve DNS correctness, safe deployment defaults, and platform-neutral paths.

Before opening a change, run:

```bash
go test -mod=vendor ./...
go test -race -mod=vendor ./...
go vet -mod=vendor ./...
go mod verify
```

Run the same checks on Windows with PowerShell as well as on Unix-like systems when changing listeners, persistence, filesystem paths, or service behavior. Build artifacts are local outputs; do not commit binaries, runtime state, credentials, generated certificates, or local blocklists.

Changes that affect configuration, persistence, policy precedence, DNS forwarding, or authentication should include regression coverage and update the relevant file under `docs/`. Do not commit runtime state, credentials, generated certificates, binaries, or local blocklists.

There is no project CI or automated build workflow. Contributors are responsible for validating their own changes before submitting them.
