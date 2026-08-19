# Contributing

Contributions should preserve DNS correctness, safe deployment defaults, and platform-neutral paths.

Before opening a change, run:

```bash
go test -mod=vendor ./...
go test -race -mod=vendor ./...
go vet -mod=vendor ./...
go mod verify
```

Run the same checks on Windows with PowerShell as well as on Unix-like systems when changing listeners, persistence, filesystem paths, or service behavior. Release binaries are built deliberately with `scripts/build.ps1` or `scripts/build.sh`; the repository workflow never publishes artifacts automatically.

Changes that affect configuration, persistence, policy precedence, DNS forwarding, or authentication should include regression coverage and update the relevant file under `docs/`. Do not commit runtime state, credentials, generated certificates, binaries, or local blocklists.

The repository workflow is manual-only. Maintainers decide when checks and release builds run.
