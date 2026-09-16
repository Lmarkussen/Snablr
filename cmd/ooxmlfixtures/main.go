// Command ooxmlfixtures generates real OOXML (DOCX/XLSX/PPTX) credential
// regression fixtures. Run it once to (re)write the testdata files; it is not
// part of the shipped tool.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	root := filepath.Join("testdata", "office-credential-regression")
	if err := os.MkdirAll(root, 0o755); err != nil {
		panic(err)
	}
	for name, content := range fixtures() {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, content, 0o644); err != nil {
			panic(err)
		}
		fmt.Printf("wrote %s (%d bytes)\n", path, len(content))
	}
}
