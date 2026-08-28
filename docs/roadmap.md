# Roadmap

These items are intentionally not implemented in the current release line.

## Authenticated Share Listing

Add a future `--list-shares` mode that authenticates using the selected password,
NTLM-hash, or Kerberos identity, tests actual share accessibility/readability, and
prints only shares available to that authenticated user before exiting. It should
not start a normal file scan.

## SECURITY + SYSTEM Secrets

Add bounded analysis of LSA secrets and cached material from SECURITY/SYSTEM
artifact pairs, with the same secret-handling and validation requirements as the
current SAM+SYSTEM path.

## NTDS.DIT + SYSTEM

Add validated offline analysis of domain credential material from NTDS.DIT paired
with SYSTEM. This is not currently implemented.
