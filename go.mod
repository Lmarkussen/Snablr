module snablr

go 1.24.0

replace github.com/mattn/go-sqlite3 => ./third_party/go-sqlite3

require gopkg.in/yaml.v3 v3.0.1

require (
	github.com/go-ldap/ldap/v3 v3.4.12
	github.com/hirochachacha/go-smb2 v1.1.0
	github.com/mattn/go-sqlite3 v1.14.28
)

require (
	github.com/Azure/go-ntlmssp v0.1.0 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
)
