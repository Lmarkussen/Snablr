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

## Other corpora

- `--expanded` writes the deterministic recursive lab corpus (deep folder
  trees, archives, and the full template set).
- `--credentials-v2` writes an independent, randomized credential acceptance
  corpus with positive, review, and negative-control files. Its manifest
  records the expected username/password pairs for each file.
- `--artifacts` writes the high-value artifact corpus: disk and memory images,
  Kerberos tickets, LSASS dumps, remote-access stores, and files larger than the
  scanner read limit.
- `--clean-prefix` removes previously seeded content under `--seed-prefix`
  before writing, so a corpus can be re-seeded in place.

WIM templates need the external `wimlib-imagex` executable. When it is not on
`PATH`, the generator skips WIM templates and leaves them out of the manifest.

## Verifying a scan against a manifest

`snablr-seed verify` compares a scan with a manifest. Pass exactly one of
`--results` (a JSON scan result) or `--db` (a Snablr SQLite scan database,
opened read-only). With `--db`, it also checks the persisted credential pairs.
Use `--scan-id` when the database holds several scans.

```text
snablr scan --targets fileserver.example.test --username test_operator \
  --password SYNTHETIC_PASSWORD --share SyntheticShare \
  --path Credentials-Finder-V2 --dbname credentials-v2.db --no-outfile
snablr-seed verify --manifest credentials-finder-v2.json --db credentials-v2.db
```

The report lists expected items found and missed per category and class,
mismatched triage classes, and matched credential pairs. It also reports
negative controls that produced actionable findings (false positives) and
review material that surfaced as findings.

Generated files are synthetic regression material. Do not place live data,
real credentials, customer names, or local workstation paths in fixtures,
manifests, documentation, or commits.
