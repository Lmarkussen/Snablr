package windowsinspect

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"

	"snablr/internal/textdecode"
)

const MaxBytes = 4 * 1024 * 1024

type Candidate struct {
	FilePath  string
	Name      string
	Extension string
	Size      int64
}

type Match struct {
	ID              string
	Name            string
	Description     string
	Severity        string
	Confidence      string
	Category        string
	SignalType      string
	Match           string
	MatchedText     string
	Snippet         string
	Context         string
	LineNumber      int
	Tags            []string
	ObservationKey  string
	ValidationBasis string
}

func New() Inspector { return Inspector{} }

type Inspector struct{}

func (Inspector) NeedsContent(candidate Candidate) bool {
	name := strings.ToLower(strings.TrimSpace(candidate.Name))
	ext := strings.ToLower(strings.TrimSpace(candidate.Extension))
	if ext == ".xml" || ext == ".reg" || ext == ".ini" {
		return true
	}
	for _, marker := range []string{"unattend", "autounattend", "customsettings", "bootstrap", "applicationhost", "scheduledtasks", "groups.xml", "services.xml", "drives.xml", "registry.xml", "task-sequence", "tasksequence"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return candidate.Size > 0 && candidate.Size <= MaxBytes && ext == ""
}

func (Inspector) InspectContent(candidate Candidate, content []byte) []Match {
	if len(content) == 0 || len(content) > MaxBytes {
		return nil
	}
	decoded := textdecode.Normalize(content)
	if decoded == "" {
		return nil
	}
	if strings.EqualFold(candidate.Extension, ".reg") || looksLikeRegistryExport(decoded) {
		return inspectRegistry(decoded, string(content))
	}
	return inspectXML(decoded, string(content))
}

func inspectXML(text, raw string) []Match {
	decoder := xml.NewDecoder(strings.NewReader(text))
	var root string
	var depth int
	var hasActions, hasPrincipals, hasRegistration, hasTriggers bool
	var gppItems []string
	var valid = true
	for {
		token, err := decoder.Token()
		if err != nil {
			if err != io.EOF {
				valid = false
			}
			break
		}
		switch value := token.(type) {
		case xml.StartElement:
			local := strings.ToLower(strings.TrimSpace(value.Name.Local))
			if root == "" {
				root = local
			}
			depth++
			switch local {
			case "actions":
				hasActions = true
			case "principals":
				hasPrincipals = true
			case "registrationinfo":
				hasRegistration = true
			case "triggers":
				hasTriggers = true
			case "user", "group", "task", "service", "drive", "registry":
				if depth > 1 {
					gppItems = append(gppItems, local)
				}
			}
		case xml.EndElement:
			depth--
		}
	}
	if !valid || root == "" {
		return nil
	}
	base := func(id, name, description, key string, tags []string) Match {
		return Match{ID: id, Name: name, Description: description, Severity: "medium", Confidence: "high", Category: "windows-deployment", SignalType: "validated", Match: root, MatchedText: raw, Snippet: raw, Context: raw, Tags: tags, ObservationKey: key, ValidationBasis: "bounded Windows-specific XML structure"}
	}
	var matches []Match
	switch root {
	case "unattend", "autounattend":
		if strings.Contains(strings.ToLower(text), "component") && strings.Contains(strings.ToLower(text), "settings") {
			matches = append(matches, base("windowsinspect.unattend.structured", "Windows Unattended Setup XML", "A bounded XML document has an unattended-setup root and supported component/settings structure.", root, []string{"windows", "deployment", "unattend", "structured"}))
		}
	case "task":
		if hasActions && hasPrincipals && (hasRegistration || hasTriggers) {
			matches = append(matches, base("windowsinspect.scheduled_task.structured", "Windows Scheduled Task XML", "A bounded XML document has Task Scheduler structure with actions, principals, and registration or trigger metadata.", root, []string{"windows", "scheduled-task", "structured"}))
		}
	case "groups":
		for index := range gppItems {
			matches = append(matches, base("windowsinspect.gpp.groups", "Group Policy Preferences Groups XML", "A bounded Groups.xml document contains a supported item scope.", fmt.Sprintf("groups:item:%d:%s", index, gppItems[index]), []string{"windows", "gpp", "groups", "structured"}))
		}
	case "scheduledtasks", "services", "drives", "registry":
		for index := range gppItems {
			id := "windowsinspect.gpp." + root
			matches = append(matches, base(id, "Group Policy Preferences "+strings.Title(root)+" XML", "A bounded Group Policy Preferences document contains a supported item scope.", fmt.Sprintf("%s:item:%d:%s", root, index, gppItems[index]), []string{"windows", "gpp", root, "structured"}))
		}
	}
	return matches
}

var registryHeader = regexp.MustCompile(`(?im)^\s*Windows Registry Editor Version (5\.00|5\.0)\s*$`)
var registryKey = regexp.MustCompile(`(?m)^\s*\[[^\]\r\n]+\]\s*$`)
var registryValue = regexp.MustCompile(`(?m)^\s*@?"[^"\r\n]+"\s*=|^\s*@\s*=`)

func looksLikeRegistryExport(text string) bool { return registryHeader.MatchString(text) }

func inspectRegistry(text, raw string) []Match {
	if !registryHeader.MatchString(text) || !registryKey.MatchString(text) {
		return nil
	}
	keyCount := len(registryKey.FindAllString(text, -1))
	valueCount := len(registryValue.FindAllString(text, -1))
	if keyCount == 0 {
		return nil
	}
	status := "valid Registry Editor text export"
	if valueCount == 0 {
		status = "header and key sections present; no value assignments"
	}
	return []Match{{
		ID: "windowsinspect.registry_export.structured", Name: "Windows Registry Editor Export", Description: fmt.Sprintf("A bounded Registry Editor text export contains %d key section(s) and %d value assignment(s).", keyCount, valueCount), Severity: "low", Confidence: "high", Category: "windows-deployment", SignalType: "validated", Match: status, MatchedText: raw, Snippet: raw, Context: raw, Tags: []string{"windows", "registry", "structured"}, ObservationKey: fmt.Sprintf("keys:%d:values:%d", keyCount, valueCount), ValidationBasis: "bounded Registry Editor header, key-section, and assignment grammar",
	}}
}
