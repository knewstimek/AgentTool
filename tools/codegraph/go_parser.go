package codegraph

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"strconv"
	"strings"
)

// parseGoSource uses the Go standard library parser so Go indexing does not
// depend on an external toolchain and retains language-specific structure that
// the generic tree-sitter output flattens away.
func parseGoSource(source string) (*ParseResult, error) {
	fset := token.NewFileSet()
	file, parseErr := parser.ParseFile(fset, "source.go", source, parser.AllErrors)
	if file == nil {
		return nil, parseErr
	}
	result := &ParseResult{}
	pkg := file.Name.Name
	qualify := func(parts ...string) string {
		var nonEmpty []string
		for _, part := range parts {
			if part != "" {
				nonEmpty = append(nonEmpty, part)
			}
		}
		return strings.Join(nonEmpty, "::")
	}
	position := func(node ast.Node) (line, endLine, col int) {
		start := fset.Position(node.Pos())
		end := fset.Position(node.End())
		return start.Line, end.Line, start.Column
	}
	sourceText := func(node ast.Node) string {
		if node == nil {
			return ""
		}
		start := fset.Position(node.Pos()).Offset
		end := fset.Position(node.End()).Offset
		if start < 0 || end < start || end > len(source) {
			return ""
		}
		return strings.TrimSpace(source[start:end])
	}

	imports := make(map[string]string)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			importPath = strings.Trim(spec.Path.Value, `"`)
		}
		alias := path.Base(importPath)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		imports[alias] = importPath
		line, endLine, col := position(spec)
		result.Imports = append(result.Imports, Symbol{
			Capture: "import", NodeType: "import_spec", Name: importPath,
			QualifiedName: alias, RawText: sourceText(spec), Line: line, EndLine: endLine, Col: col,
		})
	}

	definedFunctions := make(map[string][]string)
	definedMethods := make(map[string][]string)
	definedTypes := make(map[string]bool)
	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.GenDecl:
			if decl.Tok == token.VAR || decl.Tok == token.CONST {
				extractGoValueFacts(result, fset, "", "global", decl.Specs, nil)
			}
			if decl.Tok != token.TYPE {
				continue
			}
			for _, rawSpec := range decl.Specs {
				spec, ok := rawSpec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				line, endLine, col := position(spec)
				kind := goTypeKind(spec)
				result.Classes = append(result.Classes, Symbol{
					Capture: "class", NodeType: "type_spec", Name: spec.Name.Name,
					QualifiedName: qualify(pkg, spec.Name.Name), Kind: kind,
					RawText: sourceText(spec), Line: line, EndLine: endLine, Col: col,
				})
				definedTypes[spec.Name.Name] = true
				extractGoTypeMembers(result, fset, source, pkg, spec, qualify)
			}
		case *ast.FuncDecl:
			receiver := ""
			kind := "function"
			if decl.Recv != nil && len(decl.Recv.List) > 0 {
				receiver = goBaseTypeName(decl.Recv.List[0].Type)
				kind = "method"
			}
			line, endLine, col := position(decl)
			qn := qualify(pkg, receiver, decl.Name.Name)
			result.Functions = append(result.Functions, Symbol{
				Capture: "function", NodeType: "func_decl", Name: decl.Name.Name,
				QualifiedName: qn, Kind: kind, Signature: goFunctionSignature(sourceText(decl)),
				Receiver: receiver, Line: line, EndLine: endLine, Col: col, Scope: receiver,
			})
			owner := qn
			if decl.Recv != nil {
				for _, field := range decl.Recv.List {
					for _, name := range field.Names {
						line, _, _ := position(field)
						result.Variables = append(result.Variables, VariableFact{Name: name.Name, QualifiedName: qualify(owner, name.Name), TypeName: receiver, Owner: owner, Kind: "parameter", Line: line})
					}
				}
			}
			if decl.Type.TypeParams != nil {
				for _, field := range decl.Type.TypeParams.List {
					constraint := goBaseTypeName(field.Type)
					for _, name := range field.Names {
						line, _, _ := position(field)
						result.Variables = append(result.Variables, VariableFact{Name: name.Name, QualifiedName: qualify(owner, name.Name), TypeName: constraint, Owner: owner, Kind: "type_parameter", Line: line})
					}
				}
			}
			if decl.Type.Params != nil {
				for _, field := range decl.Type.Params.List {
					typeName := goBaseTypeName(field.Type)
					for _, name := range field.Names {
						line, _, _ := position(field)
						result.Variables = append(result.Variables, VariableFact{Name: name.Name, QualifiedName: qualify(owner, name.Name), TypeName: typeName, Owner: owner, Kind: "parameter", Line: line})
					}
				}
			}
			if receiver == "" {
				definedFunctions[decl.Name.Name] = append(definedFunctions[decl.Name.Name], qn)
			} else {
				definedMethods[decl.Name.Name] = append(definedMethods[decl.Name.Name], qn)
			}
		}
	}
	for _, fn := range result.Functions {
		if fn.Kind == "method" && !stringSliceContains(definedMethods[fn.Name], fn.QualifiedName) {
			definedMethods[fn.Name] = append(definedMethods[fn.Name], fn.QualifiedName)
		}
	}

	var inspectBody func(*ast.BlockStmt, string, map[string]string)
	inspectBody = func(body *ast.BlockStmt, caller string, receiverTypes map[string]string) {
		if body == nil {
			return
		}
		ast.Inspect(body, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.FuncLit:
				line, endLine, col := position(node)
				name := "func@" + strconv.Itoa(line)
				qn := qualify(caller, name)
				result.Functions = append(result.Functions, Symbol{
					Capture: "function", NodeType: "func_literal", Name: name,
					QualifiedName: qn, Kind: "function", Signature: goFunctionSignature(sourceText(node)),
					Line: line, EndLine: endLine, Col: col,
				})
				inspectBody(node.Body, qn, cloneStringMap(receiverTypes))
				return false
			case *ast.DeclStmt:
				goRecordDeclTypes(node.Decl, receiverTypes)
				if declaration, ok := node.Decl.(*ast.GenDecl); ok {
					extractGoValueFacts(result, fset, caller, "local", declaration.Specs, receiverTypes)
				}
			case *ast.AssignStmt:
				goRecordAssignmentTypes(node, receiverTypes)
				for index, lhs := range node.Lhs {
					name, ok := lhs.(*ast.Ident)
					if !ok || index >= len(node.Rhs) {
						continue
					}
					line, _, _ := position(lhs)
					if literal, ok := node.Rhs[index].(*ast.FuncLit); ok {
						targetLine, _, _ := position(literal)
						result.Variables = append(result.Variables, VariableFact{Name: name.Name, QualifiedName: qualify(caller, name.Name), TypeName: "function", Owner: caller, Kind: "callback", Target: qualify(caller, "func@"+strconv.Itoa(targetLine)), Line: line})
					} else if target, ok := goUnwrapCallee(node.Rhs[index]).(*ast.Ident); ok && len(definedFunctions[target.Name]) == 1 {
						result.Variables = append(result.Variables, VariableFact{Name: name.Name, QualifiedName: qualify(caller, name.Name), TypeName: "function", Owner: caller, Kind: "callback", Target: definedFunctions[target.Name][0], Line: line})
					} else if typeName := receiverTypes[name.Name]; typeName != "" {
						result.Variables = append(result.Variables, VariableFact{Name: name.Name, QualifiedName: qualify(caller, name.Name), TypeName: typeName, Owner: caller, Kind: "local", Line: line})
					}
				}
			case *ast.CallExpr:
				if ident, ok := goUnwrapCallee(node.Fun).(*ast.Ident); ok && definedTypes[ident.Name] {
					return true // conversion, not a call edge
				}
				name := goCalleeName(node.Fun)
				if name == "" {
					return true
				}
				raw := sourceText(node.Fun)
				receiver := ""
				if selector := goSelector(node.Fun); selector != nil {
					receiver = sourceText(selector.X)
				}
				qualified := raw
				resolution := "lexical"
				if ident, ok := goUnwrapCallee(node.Fun).(*ast.Ident); ok {
					if targets := definedFunctions[ident.Name]; len(targets) == 1 {
						qualified = targets[0]
						resolution = "exact"
					}
				} else if selector := goSelector(node.Fun); selector != nil {
					if ident, ok := selector.X.(*ast.Ident); ok {
						if importPath, ok := imports[ident.Name]; ok {
							qualified = qualify(importPath, selector.Sel.Name)
							resolution = "exact"
						} else {
							typeName := receiverTypes[ident.Name]
							if typeName == "" && definedTypes[ident.Name] {
								typeName = ident.Name
							}
							target := qualify(pkg, typeName, selector.Sel.Name)
							if typeName != "" && stringSliceContains(definedMethods[selector.Sel.Name], target) {
								qualified = target
								resolution = "exact"
							}
						}
					}
				}
				line, endLine, col := position(node.Fun)
				result.Calls = append(result.Calls, Symbol{
					Capture: "callee", NodeType: "call_expr", Name: name,
					QualifiedName: qualified, RawText: raw, Receiver: receiver,
					Resolution: resolution, Confidence: goResolutionConfidence(resolution),
					Line: line, EndLine: endLine, Col: col, Scope: caller,
				})
			}
			return true
		})
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			receiver := ""
			receiverTypes := make(map[string]string)
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				receiver = goBaseTypeName(fn.Recv.List[0].Type)
				for _, field := range fn.Recv.List {
					for _, name := range field.Names {
						receiverTypes[name.Name] = receiver
					}
				}
			}
			goRecordFieldTypes(fn.Type.Params, receiverTypes)
			inspectBody(fn.Body, qualify(pkg, receiver, fn.Name.Name), receiverTypes)
		}
	}

	// Go's parser can return a useful partial tree alongside syntax errors.
	// Keep those structural results, matching tree-sitter's error-tolerant mode.
	enhanceSourceFacts("go", source, result)
	return result, nil
}

func goRecordFieldTypes(fields *ast.FieldList, receiverTypes map[string]string) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		typeName := goBaseTypeName(field.Type)
		for _, name := range field.Names {
			receiverTypes[name.Name] = typeName
		}
	}
}

func goRecordDeclTypes(decl ast.Decl, receiverTypes map[string]string) {
	gen, ok := decl.(*ast.GenDecl)
	if !ok || gen.Tok != token.VAR {
		return
	}
	for _, rawSpec := range gen.Specs {
		spec, ok := rawSpec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range spec.Names {
			typeName := goBaseTypeName(spec.Type)
			if typeName == "" && i < len(spec.Values) {
				typeName = goExpressionType(spec.Values[i], receiverTypes)
			}
			if typeName != "" {
				receiverTypes[name.Name] = typeName
			}
		}
	}
}

func goRecordAssignmentTypes(assign *ast.AssignStmt, receiverTypes map[string]string) {
	for i, lhs := range assign.Lhs {
		name, ok := lhs.(*ast.Ident)
		if !ok || i >= len(assign.Rhs) {
			continue
		}
		if typeName := goExpressionType(assign.Rhs[i], receiverTypes); typeName != "" {
			receiverTypes[name.Name] = typeName
		}
	}
}

func goExpressionType(expr ast.Expr, receiverTypes map[string]string) string {
	switch expr := expr.(type) {
	case *ast.CompositeLit:
		return goBaseTypeName(expr.Type)
	case *ast.UnaryExpr:
		return goExpressionType(expr.X, receiverTypes)
	case *ast.Ident:
		return receiverTypes[expr.Name]
	case *ast.ParenExpr:
		return goExpressionType(expr.X, receiverTypes)
	}
	return ""
}

func cloneStringMap(source map[string]string) map[string]string {
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func stringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func goResolutionConfidence(resolution string) float64 {
	if resolution == "exact" {
		return 1
	}
	return 0.35
}

func goTypeKind(spec *ast.TypeSpec) string {
	if spec.Assign.IsValid() {
		return "alias"
	}
	switch spec.Type.(type) {
	case *ast.StructType:
		return "struct"
	case *ast.InterfaceType:
		return "interface"
	default:
		return "type"
	}
}

func extractGoTypeMembers(result *ParseResult, fset *token.FileSet, source, pkg string, spec *ast.TypeSpec, qualify func(...string) string) {
	position := func(node ast.Node) (line, endLine, col int) {
		start := fset.Position(node.Pos())
		end := fset.Position(node.End())
		return start.Line, end.Line, start.Column
	}
	sourceText := func(node ast.Node) string {
		start := fset.Position(node.Pos()).Offset
		end := fset.Position(node.End()).Offset
		if start < 0 || end < start || end > len(source) {
			return ""
		}
		return strings.TrimSpace(source[start:end])
	}
	addEmbedded := func(expr ast.Expr, kind string) {
		name := goBaseTypeName(expr)
		if name == "" {
			return
		}
		line, _, _ := position(expr)
		result.Inheritance = append(result.Inheritance, Inheritance{
			ClassName: spec.Name.Name, ParentName: name, Kind: kind, Line: line,
		})
	}

	switch typ := spec.Type.(type) {
	case *ast.StructType:
		for _, field := range typ.Fields.List {
			if len(field.Names) == 0 {
				addEmbedded(field.Type, "embeds")
				continue
			}
			typeName := goBaseTypeName(field.Type)
			for _, name := range field.Names {
				line, _, _ := position(field)
				owner := qualify(pkg, spec.Name.Name)
				result.Variables = append(result.Variables, VariableFact{Name: name.Name, QualifiedName: qualify(owner, name.Name), TypeName: typeName, Owner: owner, Kind: "field", Line: line})
			}
		}
	case *ast.InterfaceType:
		for _, field := range typ.Methods.List {
			if len(field.Names) == 0 {
				addEmbedded(field.Type, "embeds")
				continue
			}
			if _, ok := field.Type.(*ast.FuncType); !ok {
				continue
			}
			for _, name := range field.Names {
				line, endLine, col := position(field)
				result.Functions = append(result.Functions, Symbol{
					Capture: "function", NodeType: "interface_method", Name: name.Name,
					QualifiedName: qualify(pkg, spec.Name.Name, name.Name), Kind: "method",
					Signature: sourceText(field.Type), Receiver: spec.Name.Name,
					Line: line, EndLine: endLine, Col: col, Scope: spec.Name.Name,
				})
			}
		}
	}
}

func extractGoValueFacts(result *ParseResult, fset *token.FileSet, owner, kind string, specs []ast.Spec, known map[string]string) {
	for _, rawSpec := range specs {
		spec, ok := rawSpec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for index, name := range spec.Names {
			typeName := goBaseTypeName(spec.Type)
			if typeName == "" && index < len(spec.Values) {
				typeName = goExpressionType(spec.Values[index], known)
			}
			line := fset.Position(name.Pos()).Line
			result.Variables = append(result.Variables, VariableFact{Name: name.Name, QualifiedName: joinQualified(owner, name.Name), TypeName: typeName, Owner: owner, Kind: kind, Line: line})
		}
	}
}

func goBaseTypeName(expr ast.Expr) string {
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.StarExpr:
		return goBaseTypeName(expr.X)
	case *ast.ParenExpr:
		return goBaseTypeName(expr.X)
	case *ast.IndexExpr:
		return goBaseTypeName(expr.X)
	case *ast.IndexListExpr:
		return goBaseTypeName(expr.X)
	case *ast.SelectorExpr:
		return expr.Sel.Name
	}
	return ""
}

func goUnwrapCallee(expr ast.Expr) ast.Expr {
	switch expr := expr.(type) {
	case *ast.IndexExpr:
		return goUnwrapCallee(expr.X)
	case *ast.IndexListExpr:
		return goUnwrapCallee(expr.X)
	case *ast.ParenExpr:
		return goUnwrapCallee(expr.X)
	}
	return expr
}

func goSelector(expr ast.Expr) *ast.SelectorExpr {
	selector, _ := goUnwrapCallee(expr).(*ast.SelectorExpr)
	return selector
}

func goCalleeName(expr ast.Expr) string {
	switch expr := goUnwrapCallee(expr).(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.SelectorExpr:
		return expr.Sel.Name
	case *ast.FuncLit:
		return "func"
	}
	return ""
}

func goFunctionSignature(raw string) string {
	if idx := strings.Index(raw, "{"); idx >= 0 {
		raw = raw[:idx]
	}
	return strings.TrimSpace(raw)
}
