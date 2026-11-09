# Build, Install, and Release

## Official prebuilt release

Snablr v1.0.1 publishes a prebuilt **Linux AMD64** executable. This is the
supported release platform because the release binary is built and smoke
tested with CGO enabled, including a real open of a disposable Snablr SQLite
database. ARM64, macOS, and Windows release binaries are omitted until their
CGO builds and SQLite runtime behavior can be verified on those platforms.

Download the archive and checksum file from the
[v1.0.1 GitHub release](https://github.com/Lmarkussen/Snablr/releases/tag/v1.0.1):

```bash
mkdir -p snablr-v1.0.1 && cd snablr-v1.0.1
curl -fLO https://github.com/Lmarkussen/Snablr/releases/download/v1.0.1/snablr_v1.0.1_linux_amd64.tar.gz
curl -fLO https://github.com/Lmarkussen/Snablr/releases/download/v1.0.1/SHA256SUMS
sha256sum -c SHA256SUMS
tar -xzf snablr_v1.0.1_linux_amd64.tar.gz
./snablr_v1.0.1_linux_amd64/snablr version
```

The version output includes the embedded commit. Check that it matches the
commit recorded on the release page. Run the executable from the extracted
directory or install that exact file into a directory on `PATH`.

## Build the latest `main`

Source builds require Go 1.24 or later. Linux builds that use SQLite require
CGO and a C compiler. On Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y gcc libc6-dev
git clone https://github.com/Lmarkussen/Snablr.git
cd Snablr
make build
./bin/snablr version
```

`make build` builds the scanner and seeder with version, commit, and build date
metadata. To confirm which executable a shell would run, use `type -a snablr`
and `command -v snablr`. Prefer `./bin/snablr version` while working in the
checkout so an older installation earlier in `PATH` cannot be mistaken for the
new build. After replacing an installed binary, run `hash -r` in Bash and check
`type -a snablr` again.

## Build the exact v1.0.1 source

```bash
git clone https://github.com/Lmarkussen/Snablr.git
cd Snablr
git checkout --detach v1.0.1
make build VERSION=v1.0.1
./bin/snablr version
```

The version output must show `v1.0.1` and the commit associated with the tag.
For a release binary, use the official archive and verify `SHA256SUMS` as shown
above.

## Platform and CGO support

The official v1.0.1 archive is Linux AMD64 only. SQLite persistence and Finder
are required functionality; builds with `CGO_ENABLED=0` are not supported and
are not released. Building on Linux requires a C compiler and libc development
headers. macOS, Windows, and Linux ARM64 source builds may require platform
specific CGO toolchains; they are not official v1.0.1 release targets and have
not been runtime verified for this release.

## Local release checks

Run the same checks used by the release workflow:

```bash
go test ./... -count=1
go test -race ./internal/findings -count=1
go vet ./...
make release-snapshot VERSION=v1.0.1
```

The release snapshot target builds a CGO-enabled Linux AMD64 archive and writes
its SHA-256 digest to `dist/SHA256SUMS`. It does not publish a release.
