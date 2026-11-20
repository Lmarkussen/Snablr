package credentialanalysis

import (
	"strings"
	"testing"
)

func TestPythonDocumentationStrings(t *testing.T) {
	source := strings.Join([]string{
		`"""Module docstring: username admin, password DocSecret1."""`,
		`import os`,
		`EXAMPLES = r'''`,
		`- name: create`,
		`  username: admin`,
		`  password: ExampleSecret2`,
		`'''`,
		`RETURN = """ok"""  # trailing comment`,
		`CONN = """Server=db01;User ID=svc;Password=CodeSecret3;"""`,
		`PASSWORD = "CodeSecret4"`,
		`# a comment with "quotes" and '''triple''' quotes`,
		`class Client:`,
		`    '''Class docstring with password=DocSecret5.'''`,
		`    def login(self):`,
		`        """Method docstring."""`,
		`        call("""CallArgSecret6""")`,
		`        x = 1; """after semicolon DocSecret7"""`,
		`        return f"""{x} FString8"""`,
		`DOCUMENTATION = '''`,
		`options: {}`,
		`'''`,
	}, "\n")
	masked, docs := MaskPythonDocumentation(source)
	joined := strings.Join(docs, "\n")
	for _, documented := range []string{"DocSecret1", "ExampleSecret2", `"""ok"""`, "DocSecret5", "Method docstring", "DocSecret7", "options: {}"} {
		if !strings.Contains(joined, documented) {
			t.Errorf("%q not recognised as documentation", documented)
		}
		if strings.Contains(masked, documented) {
			t.Errorf("%q not masked", documented)
		}
	}
	for _, code := range []string{"CodeSecret3", "CodeSecret4", "CallArgSecret6", "FString8", "quotes"} {
		if strings.Contains(joined, code) {
			t.Errorf("%q in code treated as documentation", code)
		}
		if !strings.Contains(masked, code) {
			t.Errorf("%q in code was masked", code)
		}
	}
	if strings.Count(masked, "\n") != strings.Count(source, "\n") {
		t.Error("masking changed line numbers")
	}
	if _, docs := MaskPythonDocumentation("x = 'unterminated\nPASSWORD = 'Secret9'\n"); len(docs) != 0 {
		t.Errorf("broken source produced documentation: %q", docs)
	}
}
