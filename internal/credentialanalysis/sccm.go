package credentialanalysis

import "strings"

var sccmPasswordAccounts = map[string]string{
	"osd_join_password":        "osd_join_account",
	"osd_local_admin_password": "osd_local_admin_account",
	"domain_join_password":     "domain_join_account",
}

// harvestSCCMFields handles only explicitly named ConfigMgr credential fields
// in one already-bounded record. It intentionally does not infer credentials
// from account references or decrypt encoded values.
func harvestSCCMFields(fields map[string]string, add func(Candidate), basis string) {
	if len(fields) == 0 {
		return
	}
	for key, value := range fields {
		key = normalizeKey(key)
		accountKey, ok := sccmPasswordAccounts[key]
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		value = strings.TrimSpace(value)
		if IsPlaceholderValue(value) || looksReferenceOrTemplate(value) {
			continue
		}
		identity := strings.TrimSpace(fields[accountKey])
		if !meaningfulHashIdentity(identity) {
			identity = ""
		}
		candidate := Candidate{
			Verification:    Review,
			CredentialType:  "password",
			Identity:        identity,
			Value:           value,
			ValidationBasis: basis,
			ReviewReasons:   []string{"explicit SCCM credential field requires semantic review"},
		}
		if identity != "" {
			candidate.Verification = Confirmed
			candidate.ValidationBasis = basis
			candidate.ReviewReasons = nil
		}
		add(candidate)
	}
}

func harvestSCCMXMLScope(node *xmlHarvestNode, add func(Candidate)) {
	if node == nil || !sccmXMLScopeName(node.name) {
		return
	}
	fields := make(map[string]string)
	for _, child := range node.children {
		key := normalizeKey(firstNonEmpty(child.attrs["name"], child.attrs["key"], child.name))
		value := xmlElementValue(child)
		if key != "" && value != "" {
			fields[key] = value
		}
	}
	harvestSCCMFields(fields, add, "structured SCCM task-sequence XML record")
}

func sccmXMLScopeName(name string) bool {
	switch normalizeKey(name) {
	case "step", "task", "task_sequence", "task_sequence_step", "task_sequence_action", "action":
		return true
	default:
		return false
	}
}
