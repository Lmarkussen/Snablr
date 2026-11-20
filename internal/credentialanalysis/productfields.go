package credentialanalysis

import "strings"

// Deployment products name their credential fields after the account they
// belong to rather than using generic user/password keys: SQL Server setup
// files pair SQLSVCACCOUNT with SQLSVCPASSWORD and give the sa password as
// SAPWD, and MDT rules pair DomainAdmin with DomainAdminPassword. These
// fields are paired only inside one bounded record (an INI section or one
// object), like the SCCM fields in sccm.go.

// mdtRecordKeys are MDT rule properties; their presence marks a record as
// MDT deployment rules (CustomSettings.ini or Bootstrap.ini).
var mdtRecordKeys = []string{"deploy_root", "domain_admin", "join_domain", "join_workgroup", "os_install", "skip_admin_password", "skip_bdd_welcome", "skip_domain_membership"}

// productPasswordField reports whether key is always a product-specific
// password field (MDT AdminPassword depends on the record and is not).
func productPasswordField(key string) bool {
	key = normalizeKey(key)
	switch {
	case key == "sapwd", key == "domain_admin_password":
		return true
	case strings.HasSuffix(key, "svcpassword") && len(key) > len("svcpassword"):
		return true
	default:
		return false
	}
}

// productPasswordAccount returns the account and domain a product password
// field belongs to, read from the same record. ok is false when the field is
// not a product field in this record.
func productPasswordAccount(key string, fields map[string]string) (identity, domain string, ok bool) {
	key = normalizeKey(key)
	switch {
	case key == "sapwd":
		// SQL Server setup: the password of the built-in sa login.
		return "sa", "", true
	case strings.HasSuffix(key, "svcpassword") && len(key) > len("svcpassword"):
		// SQL Server setup service accounts: SQLSVC, AGTSVC, ASSVC, RSSVC,
		// ISSVC, FTSVC, ... and the telemetry accounts spelled *SVCACCT.
		prefix := strings.TrimSuffix(key, "password")
		return firstNonEmpty(fields[prefix+"account"], fields[prefix+"acct"]), "", true
	case key == "domain_admin_password":
		return fields["domain_admin"], fields["domain_admin_domain"], true
	case key == "admin_password":
		// MDT AdminPassword is the local Administrator password of the
		// deployed machine; elsewhere admin_password is left to the generic
		// field rules.
		for _, marker := range mdtRecordKeys {
			if fields[marker] != "" {
				return "Administrator", "", true
			}
		}
		return "", "", false
	default:
		return "", "", false
	}
}

// harvestProductFields pairs product-specific password fields with their
// accounts. A password whose account field is absent stays a review
// candidate.
func harvestProductFields(fields map[string]string, add func(Candidate), basis string) {
	for _, key := range sortedKeys(fields) {
		identity, domain, ok := productPasswordAccount(key, fields)
		if !ok {
			continue
		}
		value := strings.TrimSpace(fields[key])
		if value == "" || IsPlaceholderValue(value) || looksReferenceOrTemplate(value) {
			continue
		}
		identity = strings.TrimSpace(identity)
		if !meaningfulHashIdentity(identity) || looksReferenceOrTemplate(identity) {
			identity = ""
		}
		candidate := Candidate{
			Verification:   Review,
			CredentialType: "password",
			Value:          value,
			ReviewReasons:  []string{"explicit product credential field has no account in the same record"},
		}
		if identity != "" {
			candidate.Verification = Confirmed
			candidate.Identity = identity
			candidate.Domain = strings.TrimSpace(domain)
			candidate.ValidationBasis = basis
			candidate.ReviewReasons = nil
		}
		add(candidate)
	}
}

// withoutProductFields returns fields minus the product password fields
// this record resolves, so generic field rules do not report them again.
func withoutProductFields(fields map[string]string) map[string]string {
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		if _, _, ok := productPasswordAccount(key, fields); ok {
			continue
		}
		out[key] = value
	}
	return out
}
