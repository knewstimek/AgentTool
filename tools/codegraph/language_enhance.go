package codegraph

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

var (
	csharpNamespaceRE = regexp.MustCompile(`(?m)^\s*namespace\s+([A-Za-z_][\w.]*)`)
	javaPackageRE     = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_][\w.]*)\s*;`)
	cppVariableRE     = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*)(?:\s*<[^;=()]+>)?\s*[*&]?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:[;={])`)
	typedVariableRE   = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*(?:\s*<[^;=()]+>)?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=`)
	newVariableRE     = regexp.MustCompile(`\b(?:var|let)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+([A-Z][A-Za-z0-9_]*)`)
	rustTypedRE       = regexp.MustCompile(`\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Z][A-Za-z0-9_]*)`)
	rustCtorRE        = regexp.MustCompile(`\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Z][A-Za-z0-9_]*)\s*(?:::[A-Za-z_][A-Za-z0-9_]*\s*\(|\{)`)
	pythonCtorRE      = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Z][A-Za-z0-9_]*)\s*\(`)
	aliasVariableRE   = regexp.MustCompile(`\b(?:let\s+(?:mut\s+)?|var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*[;\n]`)
	rustBlanketImplRE = regexp.MustCompile(`\bimpl\s*<([^>]*)>\s*([A-Za-z_]\w*(?:::\w+)*)\s+for\s+([A-Za-z_]\w*)`)
)

// enhanceParseResult restores structure that the compact WASM wire format
// intentionally omits. It is deterministic, source-only, and shared by the
// non-Go parsers so no compiler, language server, or external executable is
// required.
func enhanceParseResult(lang, source string, result *ParseResult) *ParseResult {
	if result == nil {
		return &ParseResult{}
	}
	lines := strings.Split(source, "\n")
	prefix := languagePrefix(lang, source)

	result.Classes = dedupeSymbols(result.Classes)
	result.Functions = dedupeSymbols(result.Functions)
	result.Imports = dedupeSymbols(result.Imports)

	for i := range result.Classes {
		s := &result.Classes[i]
		s.Kind = typeKind(lang, s.NodeType)
		s.Scope = normalizeScope(s.Scope)
		s.EndLine = declarationEndLine(lang, lines, *s)
		s.QualifiedName = joinQualified(prefix, s.Scope, s.Name)
		s.RawText = declarationHeader(lines, *s, lang)
		s.Signature = s.RawText
	}

	typeRanges := append([]Symbol(nil), result.Classes...)
	for i := range result.Functions {
		s := &result.Functions[i]
		if lang == "cpp" {
			normalizeCPPFunctionName(s)
		}
		s.Scope = normalizeScope(s.Scope)
		s.EndLine = declarationEndLine(lang, lines, *s)
		s.RawText = declarationHeader(lines, *s, lang)
		s.Signature = s.RawText
		container := smallestContaining(typeRanges, s.Line, s.EndLine)
		if container != nil && (s.Scope == "" || !isKnownType(typeRanges, s.Scope)) {
			s.Scope = container.Name
		}
		if s.NodeType == "property_declaration" {
			s.Kind = "property"
		} else if s.Scope != "" && isKnownType(typeRanges, s.Scope) {
			s.Kind = "method"
		} else {
			s.Kind = "function"
		}
		qualifiedScope := s.Scope
		if typ := findKnownType(typeRanges, s.Scope); typ != nil {
			qualifiedScope = typ.QualifiedName
		}
		if prefix != "" && (qualifiedScope == prefix || strings.HasPrefix(qualifiedScope, prefix+"::")) {
			s.QualifiedName = joinQualified(qualifiedScope, s.Name)
		} else {
			s.QualifiedName = joinQualified(prefix, qualifiedScope, s.Name)
		}
	}
	if lang == "cpp" {
		filtered := result.Functions[:0]
		for _, function := range result.Functions {
			if cppFunctionPointerRE.MatchString(function.Signature) {
				continue
			}
			filtered = append(filtered, function)
		}
		result.Functions = filtered
	}

	// Python's WASM scope only contains the class. Reconstruct nested lexical
	// scopes from exact indentation ranges, smallest declaration first.
	if lang == "python" {
		assignNestedFunctionScopes(prefix, result.Functions)
	}

	result.Imports = normalizeImports(lang, result.Imports)
	result.Calls = enhanceCalls(lang, lines, prefix, result)
	resolveReceiverTypes(lang, lines, result)
	result.Inheritance = enhanceInheritance(lang, result)
	enhanceSourceFacts(lang, source, result)
	return result
}

func normalizeCPPFunctionName(symbol *Symbol) {
	name := strings.TrimSpace(symbol.Name)
	if idx := strings.LastIndex(name, "::"); idx >= 0 {
		owner := normalizeScope(name[:idx])
		existingScope := normalizeScope(symbol.Scope)
		if existingScope == "" || owner == existingScope || strings.HasPrefix(owner, existingScope+"::") {
			symbol.Scope = owner
		} else {
			symbol.Scope = joinQualified(existingScope, owner)
		}
		symbol.Name = cleanSymbolName(strings.TrimSpace(name[idx+2:]))
		return
	}
	symbol.Name = cleanSymbolName(name)
}

// resolveReceiverTypes performs a deliberately small intraprocedural fixed
// point. Explicit declarations seed variable types; simple assignments then
// propagate them. A receiver call becomes exact only when one matching method
// exists, otherwise the database-level candidate resolver retains ambiguity.
func resolveReceiverTypes(lang string, lines []string, result *ParseResult) {
	methods := make(map[string][]string)
	for _, fn := range result.Functions {
		if fn.Kind == "method" {
			methods[fn.Name] = append(methods[fn.Name], fn.QualifiedName)
		}
	}
	for _, fn := range result.Functions {
		variables := make(map[string]string)
		aliases := make(map[string]string)
		start, end := max(fn.Line, 1), min(fn.EndLine, len(lines))
		for lineNumber := start; lineNumber <= end; lineNumber++ {
			line := lines[lineNumber-1] + "\n"
			switch lang {
			case "cpp":
				for _, match := range cppVariableRE.FindAllStringSubmatch(line, -1) {
					variables[match[2]] = match[1]
				}
			case "csharp", "java":
				for _, match := range typedVariableRE.FindAllStringSubmatch(line, -1) {
					variables[match[2]] = normalizeGenericType(match[1])
				}
				for _, match := range newVariableRE.FindAllStringSubmatch(line, -1) {
					variables[match[1]] = match[2]
				}
			case "rust":
				for _, match := range rustTypedRE.FindAllStringSubmatch(line, -1) {
					variables[match[1]] = match[2]
				}
				for _, match := range rustCtorRE.FindAllStringSubmatch(line, -1) {
					variables[match[1]] = match[2]
				}
			case "python":
				for _, match := range pythonCtorRE.FindAllStringSubmatch(line, -1) {
					variables[match[1]] = match[2]
				}
			}
			for _, match := range aliasVariableRE.FindAllStringSubmatch(line, -1) {
				aliases[match[1]] = match[2]
			}
		}
		for changed := true; changed; {
			changed = false
			for target, source := range aliases {
				if variables[target] == "" && variables[source] != "" {
					variables[target] = variables[source]
					changed = true
				}
			}
		}
		for i := range result.Calls {
			call := &result.Calls[i]
			if call.Scope != fn.QualifiedName || call.Receiver == "" {
				continue
			}
			receiverParts := strings.FieldsFunc(call.Receiver, func(r rune) bool { return r == '.' || r == ':' || r == '-' })
			if len(receiverParts) == 0 {
				continue
			}
			receiver := receiverParts[0]
			typeName := variables[receiver]
			if typeName == "" {
				continue
			}
			var matches []string
			for _, candidate := range methods[call.Name] {
				if strings.Contains(candidate, "::"+typeName+"::") || strings.HasPrefix(candidate, typeName+"::") {
					matches = append(matches, candidate)
				}
			}
			if len(matches) == 1 {
				call.QualifiedName = matches[0]
				call.Resolution = "exact"
				call.Confidence = 1
			}
		}
	}
}

func normalizeGenericType(name string) string {
	name = strings.TrimSpace(name)
	if idx := strings.Index(name, "<"); idx >= 0 {
		name = name[:idx]
	}
	return strings.TrimSpace(name)
}

func dedupeSymbols(in []Symbol) []Symbol {
	seen := make(map[string]bool, len(in))
	out := make([]Symbol, 0, len(in))
	for _, symbol := range in {
		if strings.TrimSpace(symbol.Name) == "" {
			continue
		}
		key := symbol.Name + "\x00" + symbol.NodeType + "\x00" + itoa(symbol.Line) + "\x00" + itoa(symbol.Col)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, symbol)
	}
	return out
}

func languagePrefix(lang, source string) string {
	var match []string
	switch lang {
	case "csharp":
		match = csharpNamespaceRE.FindStringSubmatch(source)
	case "java":
		match = javaPackageRE.FindStringSubmatch(source)
	}
	if len(match) == 2 {
		return strings.ReplaceAll(match[1], ".", "::")
	}
	return ""
}

func typeKind(lang, nodeType string) string {
	switch nodeType {
	case "struct_item", "struct_specifier", "struct_declaration":
		return "struct"
	case "interface_declaration":
		return "interface"
	case "trait_item":
		return "trait"
	case "enum_item", "enum_specifier", "enum_declaration":
		return "enum"
	case "union_item", "union_specifier":
		return "union"
	case "record_declaration":
		return "record"
	case "type_item":
		return "type"
	case "impl_item":
		return "impl"
	case "class_definition", "class_specifier", "class_declaration":
		return "class"
	default:
		_ = lang
		return "type"
	}
}

func normalizeScope(scope string) string {
	scope = strings.TrimSpace(scope)
	if idx := strings.Index(scope, "<"); idx >= 0 {
		scope = scope[:idx]
	}
	return strings.TrimSpace(strings.TrimPrefix(scope, "*"))
}

func joinQualified(parts ...string) string {
	var result []string
	for _, part := range parts {
		part = strings.Trim(part, ":. ")
		if part == "" {
			continue
		}
		part = strings.ReplaceAll(part, ".", "::")
		result = append(result, part)
	}
	return strings.Join(result, "::")
}

func isKnownType(types []Symbol, name string) bool {
	return findKnownType(types, name) != nil
}

func findKnownType(types []Symbol, name string) *Symbol {
	name = normalizeScope(name)
	for i := range types {
		typ := &types[i]
		if typ.Name == name || typ.QualifiedName == name || strings.HasSuffix(typ.QualifiedName, "::"+name) {
			return typ
		}
	}
	return nil
}

func smallestContaining(symbols []Symbol, line, endLine int) *Symbol {
	var best *Symbol
	for i := range symbols {
		s := &symbols[i]
		if s.Line <= line && s.EndLine >= endLine && s.EndLine >= s.Line {
			if best == nil || s.EndLine-s.Line < best.EndLine-best.Line {
				best = s
			}
		}
	}
	return best
}

func assignNestedFunctionScopes(prefix string, functions []Symbol) {
	order := make([]int, len(functions))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := functions[order[i]], functions[order[j]]
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.EndLine > b.EndLine
	})
	for pos, idx := range order {
		fn := &functions[idx]
		var parent *Symbol
		for _, prior := range order[:pos] {
			candidate := &functions[prior]
			if candidate.Line < fn.Line && candidate.EndLine >= fn.EndLine {
				if parent == nil || candidate.EndLine-candidate.Line < parent.EndLine-parent.Line {
					parent = candidate
				}
			}
		}
		if parent != nil {
			fn.Scope = parent.QualifiedName
			fn.Kind = "function"
		}
		fn.QualifiedName = joinQualified(prefix, fn.Scope, fn.Name)
	}
}

func enhanceCalls(lang string, lines []string, prefix string, result *ParseResult) []Symbol {
	aliases := importAliases(lang, result.Imports)
	full := make(map[[2]int]Symbol)
	for _, call := range result.Calls {
		if call.Capture == "call" && call.Name != "" {
			full[[2]int{call.Line, call.Col}] = call
		}
	}
	functions := result.Functions
	known := make(map[string][]string)
	for _, fn := range functions {
		known[fn.Name] = append(known[fn.Name], fn.QualifiedName)
	}
	var calls []Symbol
	seen := make(map[string]bool)
	for _, call := range result.Calls {
		if call.Capture != "callee" {
			continue
		}
		if lang == "cpp" && call.Line > 0 && call.Line <= len(lines) && strings.HasPrefix(strings.TrimSpace(lines[call.Line-1]), "#") {
			continue
		}
		raw := call.Name
		parent, hasParent := full[[2]int{call.Line, call.Col}]
		if !hasParent {
			parent, hasParent = nearestFullCall(full, call)
		}
		if hasParent {
			if sourceRaw := sourceCalleeAt(lines, parent.Line, parent.Col, call.Name); sourceRaw != "" {
				raw = sourceRaw
			} else if parent.Name != "" {
				raw = parent.Name
			}
		}
		if lang == "cpp" && call.Line > 0 && call.Line <= len(lines) && cppFunctionPointerRE.MatchString(lines[call.Line-1]) {
			declarationPrefix := strings.TrimSpace(strings.SplitN(lines[call.Line-1], "(", 2)[0])
			prefixFields := strings.Fields(declarationPrefix)
			if len(prefixFields) > 0 && cleanTypeName(prefixFields[len(prefixFields)-1]) == cleanTypeName(shortCallee(raw)) {
				continue
			}
		}
		if call.NodeType == "type_identifier" || call.Parent == "object_creation_expression" || call.Parent == "new_expression" {
			raw = strings.TrimSpace(strings.TrimPrefix(raw, "new "))
		}
		if call.Name == "" {
			call.Name = shortCallee(raw)
		}
		if call.Name == "" {
			continue
		}
		call.RawText = raw
		call.Receiver = callReceiver(raw, call.Name)
		call.Scope = ""
		if caller := smallestContaining(functions, call.Line, call.Line); caller != nil {
			call.Scope = caller.QualifiedName
		}
		call.QualifiedName = normalizeCallee(raw)
		call.Resolution = "lexical"
		call.Confidence = 0.35
		if call.Parent == "new_expression" {
			call.Name = normalizeGenericType(shortCallee(raw))
			if typ := findKnownType(result.Classes, call.Name); typ != nil {
				call.QualifiedName = typ.QualifiedName
				call.Resolution = "exact"
				call.Confidence = 1
			}
		}
		if root, rest := splitCalleeRoot(call.QualifiedName); aliases[root] != "" {
			call.QualifiedName = joinQualified(aliases[root], rest)
			call.Resolution = "exact"
			call.Confidence = 1
		}
		if targets := known[call.Name]; len(targets) == 1 && call.Receiver == "" {
			call.QualifiedName = targets[0]
			call.Resolution = "exact"
			call.Confidence = 1
		} else if call.Receiver == "self" || call.Receiver == "this" {
			if caller := smallestContaining(functions, call.Line, call.Line); caller != nil {
				owner := qualifiedOwner(caller.QualifiedName)
				target := joinQualified(owner, call.Name)
				if containsQualified(functions, target) {
					call.QualifiedName = target
					call.Resolution = "exact"
					call.Confidence = 1
				}
			}
		}
		if call.QualifiedName == "" {
			call.QualifiedName = joinQualified(prefix, call.Name)
		}
		key := itoa(call.Line) + ":" + itoa(call.Col) + ":" + call.RawText
		if !seen[key] {
			seen[key] = true
			calls = append(calls, call)
		}
	}
	return calls
}

func splitCalleeRoot(qn string) (string, string) {
	if idx := strings.Index(qn, "::"); idx >= 0 {
		return qn[:idx], qn[idx+2:]
	}
	return qn, ""
}

func importAliases(lang string, imports []Symbol) map[string]string {
	aliases := make(map[string]string)
	for _, symbol := range imports {
		name := strings.TrimSpace(symbol.Name)
		switch lang {
		case "rust":
			pathName, alias := splitImportAlias(name, " as ")
			if alias == "" {
				alias = lastPathPart(pathName, "::")
			}
			aliases[alias] = pathName
		case "java":
			if strings.HasSuffix(name, ".*") {
				continue
			}
			aliases[lastPathPart(name, ".")] = strings.ReplaceAll(name, ".", "::")
		case "python":
			if strings.HasPrefix(name, "from ") {
				parts := strings.SplitN(strings.TrimPrefix(name, "from "), " import ", 2)
				if len(parts) != 2 || strings.Contains(parts[1], ",") {
					continue
				}
				imported, alias := splitImportAlias(parts[1], " as ")
				if alias == "" {
					alias = imported
				}
				aliases[alias] = joinQualified(parts[0], imported)
			} else if strings.HasPrefix(name, "import ") {
				imported, alias := splitImportAlias(strings.TrimPrefix(name, "import "), " as ")
				if alias == "" {
					alias = strings.Split(imported, ".")[0]
				}
				aliases[alias] = strings.ReplaceAll(imported, ".", "::")
			}
		}
	}
	return aliases
}

func splitImportAlias(value, separator string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(value), separator, 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return strings.TrimSpace(value), ""
}

func lastPathPart(value, separator string) string {
	if idx := strings.LastIndex(value, separator); idx >= 0 {
		return value[idx+len(separator):]
	}
	return value
}

func nearestFullCall(full map[[2]int]Symbol, callee Symbol) (Symbol, bool) {
	var best Symbol
	found := false
	for location, candidate := range full {
		if location[0] != callee.Line || location[1] > callee.Col {
			continue
		}
		if callee.Name != "" && candidate.Name != callee.Name && !strings.HasSuffix(candidate.Name, callee.Name) {
			continue
		}
		if !found || location[1] > best.Col {
			best = candidate
			found = true
		}
	}
	return best, found
}

func sourceCalleeAt(lines []string, line, col int, calleeName string) string {
	if line <= 0 || line > len(lines) {
		return ""
	}
	text := lines[line-1]
	if col < 0 || col >= len(text) {
		return ""
	}
	text = text[col:]
	if calleeName != "" {
		for offset := 0; offset+len(calleeName) <= len(text); {
			relative := strings.Index(text[offset:], calleeName)
			if relative < 0 {
				break
			}
			index := offset + relative
			beforeOK := index == 0 || !isIdentByte(text[index-1])
			after := index + len(calleeName)
			afterOK := after == len(text) || !isIdentByte(text[after])
			if beforeOK && afterOK {
				next := strings.TrimLeft(text[after:], " \t")
				if strings.HasPrefix(next, "!") {
					return strings.TrimSpace(text[:after]) + "!"
				}
				if strings.HasPrefix(next, "(") || strings.HasPrefix(next, "<") {
					return strings.TrimSpace(text[:after])
				}
			}
			offset = index + len(calleeName)
		}
	}
	depth := 0
	for i, ch := range text {
		switch ch {
		case '<', '[':
			depth++
		case '>', ']':
			if depth > 0 {
				depth--
			}
		case '(':
			if depth == 0 {
				return strings.TrimSpace(text[:i])
			}
		case '!':
			if depth == 0 {
				return strings.TrimSpace(text[:i+1])
			}
		case ';', '{', '}':
			if depth == 0 {
				return ""
			}
		}
	}
	return ""
}

func shortCallee(raw string) string {
	raw = strings.TrimSpace(strings.TrimSuffix(raw, "!"))
	for _, separator := range []string{"->", "::", "."} {
		if idx := strings.LastIndex(raw, separator); idx >= 0 {
			raw = raw[idx+len(separator):]
		}
	}
	return strings.TrimSpace(raw)
}

func callReceiver(raw, name string) string {
	raw = strings.TrimSuffix(strings.TrimSpace(raw), "!")
	for _, separator := range []string{"->", "::", "."} {
		if idx := strings.LastIndex(raw, separator); idx >= 0 {
			return strings.TrimSpace(raw[:idx])
		}
	}
	if raw != name {
		return strings.TrimSuffix(raw, name)
	}
	return ""
}

func normalizeCallee(raw string) string {
	raw = strings.TrimSpace(strings.TrimSuffix(raw, "!"))
	raw = strings.ReplaceAll(raw, "->", "::")
	raw = strings.ReplaceAll(raw, ".", "::")
	return raw
}

func qualifiedOwner(qn string) string {
	if idx := strings.LastIndex(qn, "::"); idx >= 0 {
		return qn[:idx]
	}
	return ""
}

func containsQualified(functions []Symbol, qn string) bool {
	for _, fn := range functions {
		if fn.QualifiedName == qn {
			return true
		}
	}
	return false
}

func normalizeImports(lang string, imports []Symbol) []Symbol {
	for i := range imports {
		name := strings.TrimSpace(imports[i].Name)
		switch lang {
		case "rust":
			name = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(name, "use "), ";"))
		case "csharp":
			name = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(name, "using "), ";"))
		case "java":
			name = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(name, "import "), ";"))
		case "python":
			// Retain the complete import statement because aliases and from-imports
			// are semantically meaningful to later resolution.
		}
		imports[i].Name = name
		imports[i].RawText = name
	}
	return imports
}

func enhanceInheritance(lang string, result *ParseResult) []Inheritance {
	out := append([]Inheritance(nil), result.Inheritance...)
	for i := range out {
		switch lang {
		case "rust":
			out[i].Kind = "implements"
		case "go":
			out[i].Kind = "embeds"
		case "csharp":
			out[i].Kind = "base"
		case "java":
			out[i].Kind = "extends"
			for _, typ := range result.Classes {
				if typ.Name == out[i].ClassName && strings.Contains(typ.RawText, "implements ") {
					out[i].Kind = "implements"
				}
			}
		default:
			out[i].Kind = "inherits"
		}
	}
	if lang == "rust" {
		for _, typ := range result.Classes {
			if typ.Kind != "impl" {
				continue
			}
			parts := strings.SplitN(typ.Name, " for ", 2)
			if len(parts) == 2 {
				out = append(out, Inheritance{ClassName: normalizeScope(parts[1]), ParentName: normalizeScope(parts[0]), Kind: "implements", Line: typ.Line})
			}
			if match := rustBlanketImplRE.FindStringSubmatch(typ.RawText); match != nil {
				for _, parameter := range splitTopLevel(match[1]) {
					bound := strings.SplitN(parameter, ":", 2)
					if len(bound) == 2 && strings.TrimSpace(bound[0]) == match[3] {
						out = append(out, Inheritance{ClassName: "@blanket:" + firstTypeBound(bound[1]), ParentName: normalizeScope(match[2]), Kind: "blanket_implements", Line: typ.Line})
					}
				}
			}
		}
	}
	return out
}

func declarationEndLine(lang string, lines []string, symbol Symbol) int {
	if symbol.Line <= 0 || symbol.Line > len(lines) {
		return symbol.Line
	}
	if lang == "python" {
		return pythonBlockEnd(lines, symbol.Line, symbol.Col)
	}
	return braceBlockEnd(lines, symbol.Line, symbol.Col)
}

func pythonBlockEnd(lines []string, startLine, col int) int {
	end := startLine
	for i := startLine; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeftFunc(line, unicode.IsSpace))
		if indent <= col {
			break
		}
		end = i + 1
	}
	return end
}

func braceBlockEnd(lines []string, startLine, col int) int {
	depth := 0
	started := false
	inBlockComment := false
	quote := rune(0)
	escaped := false
	for i := startLine - 1; i < len(lines); i++ {
		line := lines[i]
		start := 0
		if i == startLine-1 && col > 0 && col < len(line) {
			start = col
		}
		for j := start; j < len(line); j++ {
			ch := rune(line[j])
			next := byte(0)
			if j+1 < len(line) {
				next = line[j+1]
			}
			if inBlockComment {
				if ch == '*' && next == '/' {
					inBlockComment = false
					j++
				}
				continue
			}
			if quote != 0 {
				if escaped {
					escaped = false
				} else if ch == '\\' {
					escaped = true
				} else if ch == quote {
					quote = 0
				}
				continue
			}
			if ch == '/' && next == '/' {
				break
			}
			if ch == '/' && next == '*' {
				inBlockComment = true
				j++
				continue
			}
			if ch == '\'' || ch == '"' || ch == '`' {
				quote = ch
				continue
			}
			switch ch {
			case '{':
				started = true
				depth++
			case '}':
				if started {
					depth--
					if depth == 0 {
						return i + 1
					}
				}
			case ';':
				if !started {
					return i + 1
				}
			}
		}
	}
	return startLine
}

func declarationHeader(lines []string, symbol Symbol, lang string) string {
	if symbol.Line <= 0 || symbol.Line > len(lines) {
		return ""
	}
	line := lines[symbol.Line-1]
	if symbol.Col >= 0 && symbol.Col < len(line) {
		line = line[symbol.Col:]
	}
	line = strings.TrimSpace(line)
	if lang == "python" {
		return strings.TrimSpace(line)
	}
	var header strings.Builder
	for index := symbol.Line - 1; index < len(lines) && index < symbol.Line+15; index++ {
		part := lines[index]
		if index == symbol.Line-1 {
			part = line
		}
		stop := len(part)
		if brace := strings.Index(part, "{"); brace >= 0 && brace < stop {
			stop = brace
		}
		if semicolon := strings.Index(part, ";"); semicolon >= 0 && semicolon < stop {
			stop = semicolon
		}
		if header.Len() > 0 {
			header.WriteByte(' ')
		}
		header.WriteString(strings.TrimSpace(part[:stop]))
		if stop < len(part) {
			break
		}
	}
	return strings.TrimSpace(strings.TrimSuffix(header.String(), ";"))
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}
