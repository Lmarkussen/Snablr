# Example Commands

## Validate Rules

```bash
./bin/snablr rules validate --config configs/config.yaml
```

## Test a Rule File

```bash
./bin/snablr rules test \
  --rule configs/rules/default/content.yml \
  --input testdata/rules/fixtures/content/password-assignment.conf \
  --verbose
```

## Scan a Single Host

```bash
./bin/snablr scan \
  --targets 10.0.0.5 \
  --user 'EXAMPLE\user' \
  --pass 'REPLACE_ME' \
  --output-format console
```

## SMB Authentication Modes

Password authentication:

```bash
./bin/snablr scan --targets FILE01.example.com --no-ldap \
  --smb-auth password --username 'DOMAIN\\user' --password '<password>'
```

NTLM hash/pass-the-hash authentication:

```bash
./bin/snablr scan --targets FILE01.example.com --no-ldap \
  --smb-auth ntlm-hash --username 'DOMAIN\\user' --nt-hash '<32-hex-nt-hash>'
```

Kerberos using an existing FILE ccache:

```bash
KRB5CCNAME=/path/to/ccache ./bin/snablr scan \
  --targets FILE01.example.com --no-ldap --smb-auth kerberos \
  --smb-hostname FILE01.example.com
```

## List Shares Accessible to the Authenticated User

`--list-shares` authenticates with the selected SMB mode, validates each
candidate with a tree connect and root directory listing, prints only readable
filesystem shares, and exits without a file scan or persistent scan state.

```bash
./bin/snablr scan --targets FILE01.example.com --no-ldap \
  --smb-auth password --username 'DOMAIN\\user' --password '<password>' \
  --list-shares

./bin/snablr scan --targets FILE01.example.com --no-ldap \
  --smb-auth ntlm-hash --username 'DOMAIN\\user' \
  --nt-hash '<32-hex-nt-hash>' --list-shares

KRB5CCNAME=/path/to/ccache ./bin/snablr scan \
  --targets FILE01.example.com --no-ldap --smb-auth kerberos \
  --smb-hostname FILE01.example.com --list-shares
```

Results reflect shares accessible to the authenticated identity. Output is
grouped by target, shows UNC share roots and a readable-share count, and
omits `IPC$` and `PRINT$` as non-filesystem shares. Routine discovery chatter
is suppressed unless debug logging is enabled.

## Incremental Credential Pivot

```bash
./bin/snablr scan --targets FILE01.example.com --no-ldap \
  --smb-auth password --username 'DOMAIN\\user-a' --password '<password-a>' \
  --state-dir ./state --incremental

./bin/snablr scan --targets FILE01.example.com --no-ldap \
  --smb-auth ntlm-hash --username 'DOMAIN\\user-b' --nt-hash '<32-hex-nt-hash-b>' \
  --state-dir ./state --incremental

./bin/snablr scan --targets FILE01.example.com --no-ldap \
  --smb-auth password --username 'DOMAIN\\user-b' --password '<password-b>' \
  --state-dir ./state --force-rescan
```

The second scan re-enumerates access but can skip unchanged, successfully
inspected content from the first scan. It does not reuse the first user's
directory traversal as a substitute for discovery.

## Run a Resumable Scan With Multiple Exports

```bash
./bin/snablr scan \
  --config examples/config.basic.yaml \
  --output-format all \
  --json-out results.json \
  --html-out report.html \
  --csv-out findings.csv \
  --md-out summary.md
```

## Limit Scope to Specific Shares and Paths

```bash
./bin/snablr scan \
  --config configs/config.yaml \
  --share Finance \
  --exclude-share Backups \
  --path Policies/ \
  --max-depth 4
```
