# Releasing

DNSLeaf does not build or publish artifacts automatically on push. Releases are deliberate maintainer actions.

## Pre-release checks

Run these commands from the repository root:

```bash
go test -mod=vendor ./...
go test -race -mod=vendor ./...
go test -mod=mod ./...
go vet -mod=vendor ./...
go mod verify
git diff --check
```

The manual GitHub Actions workflow runs the repository checks but does not publish a binary. A successful test run compiles packages; it is still useful to run an explicit release build locally.

## Manual build

Use a clean checkout and write output outside the source tree or to a disposable, ignored path:

```powershell
go build -mod=vendor -trimpath -ldflags "-s -w" -o dnsleaf.exe .
Get-FileHash .\dnsleaf.exe -Algorithm SHA256
```

```bash
go build -mod=vendor -trimpath -ldflags '-s -w' -o dnsleaf .
sha256sum dnsleaf
```

Build each target separately when publishing multi-platform artifacts. Do not include `config.json`, `stats.json`, `gravity/`, generated certificates, or local blocklists in a release archive.

## Publication checklist

1. Confirm the working tree is clean and all phase commits are pushed.
2. Run the complete checks above with the intended Go toolchain.
3. Build and hash each release binary.
4. Verify a fresh configuration using `dnsleaf --config config.json validate`.
5. Create an annotated version tag and publish the binaries and checksums manually.
6. Test UDP, TCP, the administration panel, and any enabled encrypted listener from a fresh deployment.
