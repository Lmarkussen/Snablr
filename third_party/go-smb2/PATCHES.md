# Snablr go-smb2 maintenance copy

This directory is a maintained source copy of `github.com/hirochachacha/go-smb2`
version 1.1.0, based on upstream commit
`82da9adcf15307deb147fbe4a0732d0e0b657e2c`.

It contains the reviewed generic authentication-mechanism/session-setup change
and asynchronous SMB response handling change required by Snablr. The upstream
BSD 3-Clause license and copyright notice are preserved in `LICENSE`.

The changes were implemented independently from SMB protocol semantics; no
implementation code was copied into Snablr from another project.
