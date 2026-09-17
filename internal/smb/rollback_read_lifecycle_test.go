package smb

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestSMBOperationsAreNotDetachedFromCaller is the regression guard for the
// unstable recovery stack: SMB operations must run on the caller's goroutine so
// a session can never be torn down or replaced while an abandoned operation is
// still using it. The test enforces the invariant at the source level because
// the restored implementation drives go-smb2 directly.
func TestSMBOperationsAreNotDetachedFromCaller(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	checked := 0
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if !fileHasSMBOperation(fset, file) {
			continue
		}
		checked++
		if line, ok := firstGoStatement(fset, file); ok {
			t.Fatalf("%s:%d starts a goroutine in a file that performs SMB operations; operations must stay on the caller goroutine", name, line)
		}
	}
	if checked == 0 {
		t.Fatal("no SMB operation files were inspected")
	}
}

func fileHasSMBOperation(fset *token.FileSet, file *ast.File) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "ReadDir", "Stat", "Open", "ListSharenames", "Mount", "Read":
			found = true
			return false
		}
		return true
	})
	return found
}

func firstGoStatement(fset *token.FileSet, file *ast.File) (int, bool) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		for _, stmt := range fn.Body.List {
			if goStmt, ok := stmt.(*ast.GoStmt); ok {
				return fset.Position(goStmt.Pos()).Line, true
			}
		}
	}
	return 0, false
}
