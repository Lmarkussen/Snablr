package sccminspect

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
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
	ObservationKey  string
	ValidationBasis string
	Tags            []string
}

type Inspector struct{}

func New() Inspector { return Inspector{} }

func (Inspector) NeedsContent(candidate Candidate) bool {
	ext := strings.ToLower(strings.TrimSpace(candidate.Extension))
	name := strings.ToLower(strings.TrimSpace(candidate.Name))
	if ext == ".json" || ext == ".ini" || ext == ".xml" {
		return true
	}
	for _, marker := range []string{"sccm", "mecm", "configmgr", "tasksequence", "task-sequence", "deployment"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return ext == "" && candidate.Size > 0 && candidate.Size <= MaxBytes
}

func (Inspector) InspectContent(candidate Candidate, content []byte) []Match {
	if len(content) == 0 || len(content) > MaxBytes {
		return nil
	}
	text := textdecode.Normalize(content)
	if text == "" {
		return nil
	}
	raw := string(content)
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "{") || strings.EqualFold(candidate.Extension, ".json") {
		return inspectJSON(trimmed, raw)
	}
	if strings.HasPrefix(trimmed, "<") || strings.EqualFold(candidate.Extension, ".xml") {
		return inspectXML(trimmed, raw)
	}
	return inspectINI(trimmed, raw)
}

func match(id, name, description, key, evidence, raw string, tags ...string) Match {
	return Match{ID: id, Name: name, Description: description, Severity: "medium", Confidence: "medium", Category: "windows-deployment", SignalType: "content", Match: evidence, MatchedText: raw, Snippet: raw, Context: raw, ObservationKey: key, ValidationBasis: "bounded SCCM-shaped configuration contract; native producer/version not independently validated", Tags: append([]string{"windows", "sccm", "mecm", "structured", "sccm:synthetic-contract"}, tags...)}
}

func inspectJSON(text, raw string) []Match {
	var root any
	if json.Unmarshal([]byte(text), &root) != nil {
		return nil
	}
	var matches []Match
	walkJSON(root, "$", raw, &matches)
	return matches
}

func walkJSON(value any, path, raw string, matches *[]Match) {
	switch object := value.(type) {
	case map[string]any:
		if kind, ok := stringField(object, "sccmType"); ok {
			*matches = append(*matches, jsonRecord(kind, object, path, raw)...)
		}
		for key, child := range object {
			walkJSON(child, path+"."+key, raw, matches)
		}
	case []any:
		for index, child := range object {
			walkJSON(child, path+"["+strconv.Itoa(index)+"]", raw, matches)
		}
	}
}

func jsonRecord(kind string, object map[string]any, path, raw string) []Match {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "client", "site":
		site, siteOK := stringField(object, "siteCode")
		points := stringArray(object, "managementPoints")
		if !siteOK || !validSiteCode(site) || len(points) == 0 {
			return nil
		}
		matches := make([]Match, 0, len(points))
		for index, point := range points {
			matches = append(matches, match("sccminspect.client.management_point", "SCCM Client Management Point", "A scoped SCCM client record contains a site code and management-point reference.", fmt.Sprintf("json:%s:managementPoints[%d]", path, index), site+" -> "+point, raw, "sccm:client", "sccm:management-point"))
		}
		return matches
	case "distribution":
		site, siteOK := stringField(object, "siteCode")
		point, pointOK := stringField(object, "distributionPoint")
		share, shareOK := stringField(object, "contentShare")
		if !siteOK || !validSiteCode(site) || !pointOK || !shareOK || point == "" || share == "" {
			return nil
		}
		return []Match{match("sccminspect.infrastructure.distribution_point", "SCCM Distribution Point", "A scoped SCCM distribution-point record contains a site code, endpoint and content-share reference.", "json:"+path, site+" -> "+point+" -> "+share, raw, "sccm:distribution-point")}
	case "deployment":
		pkg, pkgOK := stringField(object, "packageId")
		collection, collectionOK := stringField(object, "collectionId")
		if !pkgOK || !collectionOK || pkg == "" || collection == "" {
			return nil
		}
		return []Match{match("sccminspect.deployment.reference", "SCCM Deployment Reference", "A scoped deployment record contains package and collection identifiers.", "json:"+path, pkg+" -> "+collection, raw, "sccm:deployment")}
	case "tasksequence":
		name, nameOK := stringField(object, "name")
		steps, ok := object["steps"].([]any)
		if !nameOK || name == "" || !ok || len(steps) == 0 {
			return nil
		}
		matches := make([]Match, 0, len(steps))
		for index, value := range steps {
			step, ok := value.(map[string]any)
			if !ok {
				continue
			}
			action, actionOK := stringField(step, "action")
			if !actionOK || action == "" {
				continue
			}
			matches = append(matches, match("sccminspect.task_sequence.step", "SCCM Task-Sequence Step", "A scoped task-sequence record contains an explicitly identified action.", fmt.Sprintf("json:%s:steps[%d]", path, index), name+" -> "+action, raw, "sccm:task-sequence"))
		}
		return matches
	}
	return nil
}

type xmlClient struct {
	XMLName          xml.Name `xml:"SCCMClient"`
	SiteCode         string   `xml:"SiteCode"`
	ManagementPoints []string `xml:"ManagementPoints>ManagementPoint"`
}
type xmlTaskSequence struct {
	XMLName xml.Name `xml:"TaskSequence"`
	Name    string   `xml:"Name"`
	Steps   []struct {
		ID        string `xml:"id,attr"`
		Action    string `xml:"Action"`
		PackageID string `xml:"PackageID"`
	} `xml:"Step"`
}
type xmlDeployment struct {
	XMLName      xml.Name `xml:"Deployment"`
	PackageID    string   `xml:"PackageID"`
	CollectionID string   `xml:"CollectionID"`
}

func inspectXML(text, raw string) []Match {
	var root struct{ XMLName xml.Name }
	if xml.Unmarshal([]byte(text), &root) != nil {
		return nil
	}
	switch strings.ToLower(root.XMLName.Local) {
	case "sccmclient":
		var value xmlClient
		if xml.Unmarshal([]byte(text), &value) != nil || !validSiteCode(value.SiteCode) || len(value.ManagementPoints) == 0 {
			return nil
		}
		result := make([]Match, 0, len(value.ManagementPoints))
		for index, point := range value.ManagementPoints {
			if strings.TrimSpace(point) != "" {
				result = append(result, match("sccminspect.client.management_point", "SCCM Client Management Point", "A scoped SCCM client XML record contains a site code and management-point reference.", fmt.Sprintf("xml:ManagementPoints/ManagementPoint[%d]", index), strings.TrimSpace(value.SiteCode)+" -> "+strings.TrimSpace(point), raw, "sccm:client", "sccm:management-point"))
			}
		}
		return result
	case "tasksequence":
		var value xmlTaskSequence
		if xml.Unmarshal([]byte(text), &value) != nil || strings.TrimSpace(value.Name) == "" {
			return nil
		}
		result := make([]Match, 0, len(value.Steps))
		for index, step := range value.Steps {
			action := strings.TrimSpace(step.Action)
			if action == "" {
				action = strings.TrimSpace(step.PackageID)
			}
			if action != "" {
				result = append(result, match("sccminspect.task_sequence.step", "SCCM Task-Sequence Step", "A scoped task-sequence XML record contains an explicitly identified action.", fmt.Sprintf("xml:Step[%d]", index), strings.TrimSpace(value.Name)+" -> "+action, raw, "sccm:task-sequence"))
			}
		}
		return result
	case "deployment":
		var value xmlDeployment
		if xml.Unmarshal([]byte(text), &value) != nil || strings.TrimSpace(value.PackageID) == "" || strings.TrimSpace(value.CollectionID) == "" {
			return nil
		}
		return []Match{match("sccminspect.deployment.reference", "SCCM Deployment Reference", "A scoped deployment XML record contains package and collection identifiers.", "xml:Deployment", strings.TrimSpace(value.PackageID)+" -> "+strings.TrimSpace(value.CollectionID), raw, "sccm:deployment")}
	}
	return nil
}

func inspectINI(text, raw string) []Match {
	sections := parseINI(text)
	var result []Match
	for section, values := range sections {
		if !strings.HasPrefix(strings.ToLower(section), "sccm.") {
			continue
		}
		prefix := "ini:" + section
		site := values["sitecode"]
		if strings.Contains(strings.ToLower(section), "client") && validSiteCode(site) && values["managementpoint"] != "" {
			result = append(result, match("sccminspect.client.management_point", "SCCM Client Management Point", "A scoped SCCM INI client section contains site and management-point fields.", prefix, site+" -> "+values["managementpoint"], raw, "sccm:client", "sccm:management-point"))
		}
		if strings.Contains(strings.ToLower(section), "distribution") && validSiteCode(site) && values["distributionpoint"] != "" && values["contentshare"] != "" {
			result = append(result, match("sccminspect.infrastructure.distribution_point", "SCCM Distribution Point", "A scoped SCCM INI distribution section contains endpoint and content-share fields.", prefix, site+" -> "+values["distributionpoint"]+" -> "+values["contentshare"], raw, "sccm:distribution-point"))
		}
		if strings.Contains(strings.ToLower(section), "deployment") && values["packageid"] != "" && values["collectionid"] != "" {
			result = append(result, match("sccminspect.deployment.reference", "SCCM Deployment Reference", "A scoped SCCM INI deployment section contains package and collection identifiers.", prefix, values["packageid"]+" -> "+values["collectionid"], raw, "sccm:deployment"))
		}
	}
	return result
}

func parseINI(text string) map[string]map[string]string {
	result := map[string]map[string]string{}
	section := ""
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			result[section] = map[string]string{}
			continue
		}
		if section == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			result[section][strings.ToLower(strings.TrimSpace(parts[0]))] = strings.Trim(strings.TrimSpace(parts[1]), "\"")
		}
	}
	return result
}
func stringField(object map[string]any, key string) (string, bool) {
	value, ok := object[key].(string)
	return strings.TrimSpace(value), ok && strings.TrimSpace(value) != ""
}
func stringArray(object map[string]any, key string) []string {
	raw, ok := object[key].([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, value := range raw {
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			result = append(result, strings.TrimSpace(text))
		}
	}
	return result
}
func validSiteCode(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) == 3 && strings.IndexFunc(value, func(r rune) bool { return r < 'A' || r > 'Z' }) == -1
}
