package output

import "strings"

// redactPrivateKeyMaterial removes valid PEM private-key bodies from safe
// reporters while retaining enough structure to explain the finding. Raw
// private keys are available only through the explicit sensitive exporter.
func redactPrivateKeyMaterial(value string) string {
	// Scanner snippets may carry escaped newlines so they remain single-line
	// evidence fields. Normalize them before looking for PEM boundaries.
	value = strings.ReplaceAll(value, `\n`, "\n")
	var out strings.Builder
	remaining := value
	for {
		begin := strings.Index(strings.ToUpper(remaining), "-----BEGIN ")
		if begin < 0 {
			out.WriteString(remaining)
			break
		}
		endHeader := strings.Index(remaining[begin:], "-----\n")
		if endHeader < 0 || !strings.Contains(strings.ToUpper(remaining[begin:begin+endHeader]), "PRIVATE KEY") {
			out.WriteString(remaining[:begin+len("-----BEGIN ")])
			remaining = remaining[begin+len("-----BEGIN "):]
			continue
		}
		headerEnd := begin + endHeader + len("-----\n")
		label := remaining[begin+len("-----BEGIN ") : begin+endHeader]
		footer := "-----END " + label + "-----"
		bodyEnd := strings.Index(remaining[headerEnd:], footer)
		if bodyEnd < 0 {
			out.WriteString(remaining[:begin])
			out.WriteString(remaining[begin:headerEnd])
			out.WriteString("[private key material redacted]")
			break
		}
		bodyEnd += headerEnd
		out.WriteString(remaining[:begin])
		out.WriteString(remaining[begin:headerEnd])
		out.WriteString("[private key material redacted]\n")
		out.WriteString(footer)
		remaining = remaining[bodyEnd+len(footer):]
	}
	return out.String()
}
