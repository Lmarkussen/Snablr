# Third-party notices

## github.com/hirochachacha/go-smb2

- Source: https://github.com/hirochachacha/go-smb2
- Baseline: v1.1.0, commit `82da9adcf15307deb147fbe4a0732d0e0b657e2c`
- License: BSD 3-Clause
- Copyright: Copyright (c) 2016 Hiroshi Ioka
- Vendored location: `third_party/go-smb2/`
- Full license: `third_party/go-smb2/LICENSE`
- Local changes: Snablr carries independently developed generic authentication
  mechanism/session-setup and asynchronous response-handling patches. See
  `third_party/go-smb2/PATCHES.md`.

The repository also contains `github.com/mattn/go-sqlite3` under
`third_party/go-sqlite3/`; its upstream license and notices are retained in
that directory. Snablr-owned application packages do not copy or adapt
implementation code from these dependencies.

## www.velocidex.com/golang/go-ese

- Source: https://github.com/Velocidex/go-ese
- Version: v0.2.0
- License: Apache License 2.0
- Use: external read-only ESE/JET catalog and table reader for NTDS.DIT
- Snablr implements NTDS account selection and credential decryption
  independently in `internal/ntdsparse`; no external implementation code is
  copied or adapted into that package.

## github.com/richardlehane/mscfb (and github.com/richardlehane/msoleps)

- Source: https://github.com/richardlehane/mscfb
- Version: v1.0.8 (direct dependency); transitively depends on
  github.com/richardlehane/msoleps v1.0.3
- License: Apache License 2.0 (both modules)
- Use: read-only Microsoft Compound File Binary (OLE/CFB) container access so
  Snablr can locate the legacy Office streams (`WordDocument`, `0Table`/`1Table`,
  `Workbook`/`Book`, `PowerPoint Document`).
- Snablr implements legacy document text extraction independently in
  `internal/legacyoffice` from the published on-disk structures (Word FIB and
  piece table, Excel BIFF8 records). No implementation code is copied,
  translated, or adapted from the dependency or from any other parser.
- Legacy `.ppt` text extraction remains deferred; the container dependency is
  still used only to recognise that a document is a legacy Office file.
