# Roadmap

These items track future work; authenticated share listing is implemented.

## Authenticated Share Listing (implemented)

`--list-shares` authenticates using the selected password, NTLM-hash, or
Kerberos identity, tests each candidate with tree connect plus root directory
listing, and prints only readable filesystem shares for that identity before
exiting. It does not start a normal file scan or persist scan state.

## SECURITY + SYSTEM Secrets

Add bounded analysis of LSA secrets and cached material from SECURITY/SYSTEM
artifact pairs, with the same secret-handling and validation requirements as the
current SAM+SYSTEM path.

## NTDS.DIT + SYSTEM

Add validated offline analysis of domain credential material from NTDS.DIT paired
with SYSTEM. This is not currently implemented.
