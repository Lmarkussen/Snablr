# Build And Release

This guide covers the simplest ways to build, test, and verify Snablr locally.

## Build Locally

Run these commands from the repository root.

Quick source build check:

```bash
go build ./...
```

Recommended local build with version metadata:

```bash
make build
```

The binary is written to:

- `bin/snablr`

Windows fallback without `make`:

```powershell
go build -o bin/snablr.exe ./cmd/snablr
.\bin\snablr.exe version
```

## Verify The Binary

Run:

```bash
./bin/snablr version
./bin/snablr --help
```

If you moved the binary into your `PATH`, you can run:

```bash
snablr version
snablr --help
```

What to look for:

- `version` prints a version string
- `--help` prints the command list

If you built with `make build`, version metadata includes version, commit, and build date.

## Run Tests

Standard local verification:

```bash
go test ./...
go vet ./...
make test
make lint
```

## Release Binaries

Snablr publishes release archives for:

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`

Artifact names follow this pattern:

- `snablr_vX.Y.Z_linux_amd64.tar.gz`
- `snablr_vX.Y.Z_windows_amd64.zip`

## How Releases Are Produced

Release automation runs in GitHub Actions when a tag matching `v*` is pushed.

Example:

```bash
git tag v1.0.0
git push origin v1.0.0
```

That workflow:

1. runs tests
2. builds the release matrix
3. injects version metadata
4. packages the archives
5. uploads them to the GitHub release

## Version Metadata

For version metadata to appear correctly in the binary, use one of:

- `make build`
- `make release-snapshot`
- a GitHub release build

Plain ad-hoc `go build` is useful for development, but typically reports `dev` / `unknown` metadata unless ldflags are supplied manually.
