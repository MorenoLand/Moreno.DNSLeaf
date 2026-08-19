# Building

DNSLeaf does not provide maintainer-built binaries or automated build workflows. Anyone who wants a binary can build it from source with the Go toolchain.

## Requirements

Go 1.25.3 or newer.

## Build

From the repository root:

```powershell
go build -mod=vendor -trimpath -o dnsleaf.exe .
```

```bash
go build -mod=vendor -trimpath -o dnsleaf .
```

`-mod=vendor` keeps the build offline and uses the checked-in dependency tree. Omit it only when intentionally resolving modules from the network.

## Verify

```bash
go test -mod=vendor ./...
go test -race -mod=vendor ./...
go test -mod=mod ./...
go vet -mod=vendor ./...
go mod verify
git diff --check
```

Build output and runtime files are ignored by Git. Do not include `config.json`, `stats.json`, `gravity/`, generated certificates, or local blocklists in a source contribution.
