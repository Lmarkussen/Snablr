![SNABLR SMB Triage Tool](assets/snablr-banner.png)

# Snablr

Snablr is an authorized SMB share triage tool. It scans permitted Windows shares,
records findings and source evidence in local SQLite, and provides an offline
Findings Engine Finder TUI for investigation.

## What it does

- Scans authorized SMB targets and shares for evidence.
- Persists findings, credential material, and provenance locally in SQLite.
- Recovers scoped credential evidence from supported files and documents.
- Preserves source paths, archive members, and other available context.
- Groups duplicate observations into logical discoveries without hiding sources.
- Separates confirmed evidence, Review material, and contextual relationships.

Supported credential evidence includes scripts and command lines (including
Windows `.cmd`/`.bat`), structured configuration, database connection strings,
text, Markdown, CSV, HTML, valid DOCX/XLSX documents, and bounded ZIP members.
Norwegian labels and Unicode values are preserved where they occur in source
material. Snablr discovers evidence; it does not authenticate with discovered
credentials.

## Scan, then investigate

A typical workflow is:

1. Scan an authorized SMB target with `snablr scan`.
2. Keep the resulting SQLite database locally.
3. Open the database in the offline Findings Engine:

```bash
snablr find
snablr find --db /path/to/scan.db
```

With no `--db`, Finder opens the default database location used by `scan`.
Use `--db` when selecting a specific scan database. Finder does not reconnect
to SMB or modify the database during review.

The Finder is organized around categories, subcategories, discoveries, and a
Details pane. Navigate with the keyboard, inspect complete evidence and source
provenance, review archive-member locations, and distinguish logical grouping
from individual source observations.

## Build and install

The official prebuilt release currently supports **Linux AMD64**. Its binary is
built with CGO and SQLite enabled. See [Building Snablr](docs/building.md) for
release downloads, source builds, verification, and platform requirements.

Download and verify the current release:

```bash
mkdir -p snablr-v1.0.1 && cd snablr-v1.0.1
curl -fLO https://github.com/Lmarkussen/Snablr/releases/download/v1.0.1/snablr_v1.0.1_linux_amd64.tar.gz
curl -fLO https://github.com/Lmarkussen/Snablr/releases/download/v1.0.1/SHA256SUMS
sha256sum -c SHA256SUMS
tar -xzf snablr_v1.0.1_linux_amd64.tar.gz
./snablr_v1.0.1_linux_amd64/snablr version
```

To build the latest source from `main`:

```bash
git clone https://github.com/Lmarkussen/Snablr.git
cd Snablr
make build
./bin/snablr version
```

To build the exact `v1.0.1` source:

```bash
git clone https://github.com/Lmarkussen/Snablr.git
cd Snablr
git checkout --detach v1.0.1
make build VERSION=v1.0.1
./bin/snablr version
```

If `snablr` resolves to an unexpected executable, inspect all PATH matches with
`type -a snablr`, then invoke the verified binary by its explicit path (for
example, `./bin/snablr version`).

For scanner and Finder build requirements, see [Getting Started](docs/getting-started.md).

For scan options and authentication examples, use the shipped command help:

```bash
snablr scan --help
snablr scan --help-advanced
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Reporting and persisted evidence](docs/reporting.md)
- [Configuration and rules](docs/configuration.md)
- [Troubleshooting](docs/troubleshooting.md)

## Authorized use

Use Snablr only against systems, shares, and data that you own or are explicitly
authorized to assess. Protect scan databases and exported evidence as sensitive
material.

## License

See the [LICENSE](LICENSE) file.
