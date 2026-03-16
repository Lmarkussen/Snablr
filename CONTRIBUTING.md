# Contributing

Thanks for contributing to Snablr.

## Development Setup

```bash
git clone <repo-url>
cd snablr
go mod download
make build
make test
```

For direct CLI checks during development:

```bash
go run ./cmd/snablr --help
go run ./cmd/snablr rules validate --config configs/config.yaml
```

## Coding Style

- Keep modules focused and readable.
- Prefer small, explicit types over cross-package coupling.
- Keep scanning logic separate from SMB, discovery, and output logic.
- Keep rule schema and runtime matching logic separate.
- Use ASCII unless an existing file clearly requires otherwise.
- Run `gofmt` on changed Go files.
- Preserve existing behavior unless the change explicitly requires a behavioral update.

## Tests

Run the standard verification set before submitting changes:

```bash
make test
make lint
go build ./...
```

The CI workflow also runs:

- `go build ./...`
- `go vet ./...`
- `go test ./...`

## Adding Rules

Default rule packs live under `configs/rules/default/`.

Organization-specific rules should usually go under `configs/rules/custom/` or under `examples/rules/custom/` as starter material.

When adding or changing rules:

- keep rule IDs unique
- prefer several readable rules over one large regex
- add descriptions that explain intent clearly
- set `enabled: false` for broad or noisy defaults unless they are safe to ship enabled
- validate changes with:

```bash
./bin/snablr rules validate --config configs/config.yaml
./bin/snablr rules test-dir --rules configs/rules/default --fixtures testdata/rules/fixtures --verbose
```

## Adding Fixtures

Test fixtures should be:

- synthetic
- safe to publish
- small and easy to understand
- clearly mapped to the rules they exercise

Preferred locations:

- `testdata/rules/fixtures/`
- `testdata/rules/unit/`

When adding a new rule or rule family, add at least one positive fixture. Add a negative fixture when the rule is broad enough to risk regressions.

## Pull Request Expectations

- explain the problem being solved
- describe any runtime or output changes
- note rule pack changes explicitly
- mention test coverage or manual verification performed
