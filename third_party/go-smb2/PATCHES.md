# Snablr go-smb2 maintenance copy

This directory is a maintained source copy of `github.com/hirochachacha/go-smb2`
version 1.1.0, based on upstream commit
`82da9adcf15307deb147fbe4a0732d0e0b657e2c`.

It contains the reviewed generic authentication-mechanism/session-setup change
and asynchronous SMB response handling change required by Snablr, and a
read-only `File.OpenStat` accessor that returns the file information from the
open response without another request. Directory listings and file information
queries limit their response buffer to the credits actually loaned: a
partial loan (other requests holding credits) previously sent a buffer
larger than its credit charge, and Windows reset the connection. A failed
request returns its loaned credits only when no response arrived: a
response with an error status (such as STATUS_NO_MORE_FILES at the end of
every directory listing, or access denied, which is reported as
os.ErrPermission) already granted credits, and returning the loan as
well overstated the credits available to concurrent requests. Requests with a
fixed credit charge of one (negotiate, session setup, tree connect and
disconnect, close, logoff) now take that credit from the balance like all
other requests; they used to be sent without it while their responses still
granted credits. The upstream
BSD 3-Clause license and copyright notice are preserved in `LICENSE`.

The changes were implemented independently from SMB protocol semantics. This
directory physically vendors upstream implementation source; no go-smb2
implementation code was copied or adapted into Snablr-owned application
packages. The local modifications to this vendored copy are described above
and in the relevant source comments/tests.
