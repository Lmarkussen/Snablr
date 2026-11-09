## Snablr v1.0.1

This release packages the SQLite-backed scanner and Finder from the tagged
source commit. Finder includes categorized global search, and scan state,
findings, credential evidence, provenance, and resume metadata persist in
SQLite.

### Supported download

- `snablr_v1.0.1_linux_amd64.tar.gz` — Linux AMD64; built with CGO enabled and
  smoke-tested against a disposable SQLite scan fixture.
- `SHA256SUMS` — SHA-256 digest for every release archive.

Linux ARM64, macOS, and Windows binaries are not included because their CGO and
SQLite runtime behavior has not been verified for this release. Do not use
CGO-disabled builds; SQLite-backed scan persistence and Finder are required.

Verify the downloaded archive with `sha256sum -c SHA256SUMS`. The executable's
`version` output reports the release version, source commit, and build date.

Release download and source build instructions are in
[Building Snablr](https://github.com/Lmarkussen/Snablr/blob/main/docs/building.md).
