# Synthetic Seeder

`snablr-seed` generates deterministic, synthetic files for local regression and
protocol-level validation. It never embeds live credentials or environment
identifiers; targets, credentials, and shares are supplied explicitly by the
operator.

## Safety

Use a disposable local SMB test service or another isolated synthetic target.
The generator writes only below the configured seed prefix and cleanup is
restricted to that prefix. Keep generated output outside the repository.

Example values are intentionally reserved or synthetic, such as
`fileserver.example.test`, `test_operator`, and `SYNTHETIC_PASSWORD`.

## Deterministic runs

Use the same target, share selection, count, depth, maximum, and random seed to
reproduce a run. Manifests record generated paths and expected classifications
so local tests can compare scan output with synthetic expectations.

The generator covers configuration, deployment, archives, databases, browser
artifacts, secret stores, cloud-shaped files, notes, scripts, and benign noise.
It also exercises HTML, JSON, CSV, Markdown, and console output paths.

Example dry run:

```text
snablr-seed --targets fileserver.example.test --username test_operator \
  --password SYNTHETIC_PASSWORD --share SyntheticShare \
  --seed-prefix SyntheticSeed --random-seed 424242 --dry-run
```

Example manifest run:

```text
snablr-seed --targets fileserver.example.test --username test_operator \
  --password SYNTHETIC_PASSWORD --share SyntheticShare \
  --manifest-out seed-manifests/synthetic.json
```

## Credential-pair audit corpus

The dedicated credentials mode creates a deterministic, inert corpus for
measuring username/password recall without changing scanner behavior:

```text
snablr-seed --credentials --targets fileserver.example.test \
  --username test_operator --password SYNTHETIC_PASSWORD \
  --share SyntheticShare --seed-prefix Credentials-Finder-V1 \
  --manifest-out credentials-finder-v1.json
```

The manifest records positive, review, and negative fixture expectations,
including logical pair counts, synthetic identities, pairing scope, origin
context, and archive provenance. The generated values are deliberately fake;
the manifest is test ground truth, not proof that a credential is valid.

Generated files are synthetic regression material. Do not place live data,
real credentials, customer names, or local workstation paths in fixtures,
manifests, documentation, or commits.
