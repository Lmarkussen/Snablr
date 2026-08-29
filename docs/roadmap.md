# Roadmap

These items track future work; authenticated share listing is implemented.

## Authenticated Share Listing (implemented)

`--list-shares` authenticates using the selected password, NTLM-hash, or
Kerberos identity, tests each candidate with tree connect plus root directory
listing, and prints only readable filesystem shares for that identity before
exiting. It does not start a normal file scan or persist scan state.

## SECURITY + SYSTEM Secrets (implemented)

Modern Vista-and-later `SECURITY` + `SYSTEM` pairs are analyzed with bounded
PolEKList AES LSA-key derivation, structured LSA-secret metadata, and cached
domain-material discovery. Raw secret bytes are not returned in findings or
reports. Legacy pre-Vista LSA protection remains deferred.

## NTDS.DIT + SYSTEM (implemented)

Modern read-only NTDS.DIT + SYSTEM analysis now recovers current domain NT hash
metadata from origin-safe loose and WIM pairs. Password history,
supplementalCredentials/Kerberos keys, and legacy database formats remain
deferred.
