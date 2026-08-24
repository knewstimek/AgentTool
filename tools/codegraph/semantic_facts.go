package codegraph

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

var (
	macroDefinitionRE     = regexp.MustCompile(`^\s*#\s*define\s+([A-Za-z_]\w*)(?:\s*\(([^)]*)\))?\s*(.*)$`)
	cppDeclarationRE      = regexp.MustCompile(`^\s*(?:(?:extern|static|const|volatile|mutable|register|thread_local|inline|constexpr)\s+)*([A-Za-z_]\w*(?:::\w+)*(?:\s*<[^;{}]+>)?(?:\s*[*&]\s*)*)\s+([A-Za-z_]\w*)\s*(?:\[[^]]*\])?\s*(?:[;=,{])`)
	cFamilyDeclarationRE  = regexp.MustCompile(`^\s*(?:(?:public|private|protected|internal|static|final|const|volatile|readonly|abstract|virtual|override|sealed|transient|synchronized)\s+)*([A-Za-z_]\w*(?:[.<>,?\[\]\s]+)?)\s+([A-Za-z_]\w*)\s*(?:[;=,{])`)
	rustLetFactRE         = regexp.MustCompile(`\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::\s*([^=;]+))?\s*=\s*([^;]+)`)
	rustFieldFactRE       = regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_]\w*)\s*:\s*([^,}]+)[,}]?`)
	cppFunctionPointerRE  = regexp.MustCompile(`\(\s*[*&]\s*([A-Za-z_]\w*)\s*\)\s*\(([^)]*)\)`)
	callbackInitializerRE = regexp.MustCompile(`=\s*[&*]?\s*([A-Za-z_]\w*(?:::\w+)*)\s*;`)
	callbackAssignmentRE  = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*=\s*[&*]?\s*([A-Za-z_]\w*(?:::\w+)*)\s*;`)
	aliasFactRE           = regexp.MustCompile(`^\s*(?:auto\s+|var\s+|let\s+(?:mut\s+)?)?([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*;`)
	initializerFactRE     = regexp.MustCompile(`\b(?:auto|var|let(?:\s+mut)?)\s+([A-Za-z_]\w*)\s*=\s*([^;]+)`)
	lambdaAssignmentRE    = regexp.MustCompile(`\b(?:auto|var|let(?:\s+mut)?)\s+([A-Za-z_]\w*)\s*=\s*(?:move\s*)?\[[^]]*\]\s*(?:\([^)]*\))?\s*\{`)
	rustClosureRE         = regexp.MustCompile(`\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*=\s*(?:move\s+)?\|([^|]*)\|`)
	csharpLambdaRE        = regexp.MustCompile(`\b(?:var|Action|Func(?:\s*<[^;=]+>)?)\s+([A-Za-z_]\w*)\s*=\s*(?:\(([^)]*)\)|([A-Za-z_]\w*))\s*=>`)
	javaLambdaRE          = regexp.MustCompile(`\b[A-Za-z_]\w*(?:\s*<[^;=]+>)?\s+([A-Za-z_]\w*)\s*=\s*\(([^)]*)\)\s*->`)
	javaMethodReferenceRE = regexp.MustCompile(`\b[A-Za-z_]\w*(?:\s*<[^;=]+>)?\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*(?:[.:]\w+)*)::([A-Za-z_]\w*)\s*;`)
	csharpDelegateRE      = regexp.MustCompile(`\b(?:Action|Func(?:\s*<[^;=]+>)?|[A-Za-z_]\w*Delegate)\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*(?:\.\w+)*)\s*;`)
	csharpExtensionRE     = regexp.MustCompile(`\(\s*this\s+`)
	rustFunctionValueRE   = regexp.MustCompile(`\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*:\s*fn\s*\(([^)]*)\)[^=;]*=\s*([A-Za-z_]\w*(?:::\w+)*)\s*;`)
	rustMacroDefinitionRE = regexp.MustCompile(`^\s*(?:macro_rules!|macro)\s+([A-Za-z_]\w*)`)
	cppUsingAliasRE       = regexp.MustCompile(`^\s*(?:template\s*<[^;]+>\s*)?using\s+([A-Za-z_]\w*)\s*=\s*([^;]+)`)
	cppTypedefAliasRE     = regexp.MustCompile(`^\s*typedef\s+(.+?)\s+([A-Za-z_]\w*)\s*;`)
	rustTypeAliasRE       = regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?type\s+([A-Za-z_]\w*)\s*(?:<([^>]*)>)?\s*=\s*([^;]+)`)
	csharpUsingAliasRE    = regexp.MustCompile(`^\s*using\s+([A-Za-z_]\w*)\s*=\s*([^;]+)`)
	goTypeAliasRE         = regexp.MustCompile(`^\s*type\s+([A-Za-z_]\w*)\s*=\s*([^\s;]+)`)
)

// enhanceSourceFacts adds compact semantic facts used by the project-wide
// resolver. It is intentionally source-only: indexing never requires a local
// compiler, language server, SDK, or target platform headers.
func enhanceSourceFacts(lang, source string, result *ParseResult) {
	lines := strings.Split(source, "\n")
	conditions := sourceConditions(lang, lines)
	for i := range result.Functions {
		function := &result.Functions[i]
		function.Arity = signatureArity(lang, function.Signature)
		function.ParameterTypes = signatureParameterTypes(lang, function.Signature)
		function.ReturnType = signatureReturnType(lang, *function)
		function.Modifiers = signatureModifiers(lang, function.Signature)
		function.Condition = conditionForLine(conditions, function.Line)
		function.SemanticKey = semanticIdentity(lang, *function)
	}
	for i := range result.Classes {
		typ := &result.Classes[i]
		typ.Condition = conditionForLine(conditions, typ.Line)
		typ.SemanticKey = semanticIdentity(lang, *typ)
		typ.Modifiers = signatureModifiers(lang, typ.Signature)
	}
	for i := range result.Calls {
		result.Calls[i].Condition = conditionForLine(conditions, result.Calls[i].Line)
		args, ok := callArgumentsForSymbol(source, lines, result.Calls[i])
		if ok {
			parts := splitTopLevel(args)
			if strings.TrimSpace(args) == "" {
				parts = nil
			}
			result.Calls[i].Arity = len(parts)
			result.Calls[i].ArgumentTypes = inferArgumentTypes(parts)
			result.Calls[i].ArgumentExpressions = strings.Join(parts, "\x1f")
		} else {
			result.Calls[i].Arity = -1
		}
	}

	if lang == "cpp" {
		extractMacros(lines, conditions, result)
	} else if lang == "rust" {
		extractRustMacros(lines, result)
	}
	extractVariableFacts(lang, lines, result)
	extractCallbackFacts(lang, lines, result)
	extractTypeAliases(lang, lines, conditions, result)
	propagateInferredVariableTypes(lang, lines, result)
	for i := range result.Variables {
		result.Variables[i].Condition = conditionForLine(conditions, result.Variables[i].Line)
		result.Variables[i].TypeArguments = genericArguments(result.Variables[i].TypeName)
	}
	for i := range result.Imports {
		result.Imports[i].Condition = conditionForLine(conditions, result.Imports[i].Line)
	}
	enhanceCallArgumentTypes(lang, source, lines, result)
}

func extractRustMacros(lines []string, result *ParseResult) {
	for index, line := range lines {
		if match := rustMacroDefinitionRE.FindStringSubmatch(line); match != nil {
			result.Macros = append(result.Macros, MacroFact{Name: match[1], QualifiedName: match[1],
				Body: strings.TrimSpace(line), FunctionLike: true, Arity: -1, Line: index + 1})
		}
	}
}

func propagateInferredVariableTypes(lang string, lines []string, result *ParseResult) {
	for index, line := range lines {
		match := initializerFactRE.FindStringSubmatch(stripLineComment(line))
		if match == nil {
			continue
		}
		lineNumber := index + 1
		owner := ""
		if function := smallestContaining(result.Functions, lineNumber, lineNumber); function != nil {
			owner = function.QualifiedName
		}
		inferred := inferSourceExpressionType(lang, strings.TrimSpace(match[2]), owner, lineNumber, result)
		if inferred == "" {
			continue
		}
		for variableIndex := len(result.Variables) - 1; variableIndex >= 0; variableIndex-- {
			variable := &result.Variables[variableIndex]
			if variable.Name == match[1] && variable.Owner == owner && variable.Line <= lineNumber && (variable.TypeName == "" || variable.TypeName == "auto" || variable.TypeName == "var") {
				variable.TypeName = inferred
				break
			}
		}
	}
}

func enhanceCallArgumentTypes(lang, source string, lines []string, result *ParseResult) {
	for callIndex := range result.Calls {
		call := &result.Calls[callIndex]
		args, ok := callArgumentsForSymbol(source, lines, *call)
		if !ok || strings.TrimSpace(args) == "" {
			continue
		}
		parts := splitTopLevel(args)
		types := strings.Split(call.ArgumentTypes, ",")
		if len(types) != len(parts) {
			types = make([]string, len(parts))
		}
		for index, expression := range parts {
			if types[index] != "" && types[index] != "unknown" {
				continue
			}
			types[index] = inferSourceExpressionType(lang, expression, call.Scope, call.Line, result)
			if types[index] == "" {
				types[index] = "unknown"
			}
		}
		call.ArgumentTypes = strings.Join(types, ",")
	}
}

func inferSourceExpressionType(lang, expression, owner string, line int, result *ParseResult) string {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return ""
	}
	if literal := inferArgumentTypes([]string{expression}); literal != "unknown" {
		return literal
	}
	if strings.HasPrefix(expression, "new ") {
		return inferredConstructorType(expression)
	}
	if open := strings.Index(expression, "("); open > 0 {
		callee := shortCallee(strings.TrimSpace(expression[:open]))
		var found string
		for _, function := range result.Functions {
			if function.Name != callee || function.ReturnType == "" {
				continue
			}
			if found != "" && found != function.ReturnType {
				return ""
			}
			found = function.ReturnType
		}
		if found != "" {
			return found
		}
		if looksLikeType(callee) {
			return callee
		}
	}
	identifier := strings.Trim(expression, "*&()[] ")
	if strings.ContainsAny(identifier, ".->: ") {
		return ""
	}
	for index := len(result.Variables) - 1; index >= 0; index-- {
		variable := result.Variables[index]
		if variable.Name != identifier || variable.Line > line {
			continue
		}
		if variable.Owner != owner && variable.Owner != qualifiedOwner(owner) && variable.Owner != "" {
			continue
		}
		if variable.TypeName != "" {
			return variable.TypeName
		}
	}
	return ""
}

func extractMacros(lines []string, conditions map[int]string, result *ParseResult) {
	for index, line := range lines {
		match := macroDefinitionRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		functionLike := strings.Contains(line, match[1]+"(")
		arity := -1
		if functionLike {
			arity = len(splitTopLevel(match[2]))
			if strings.TrimSpace(match[2]) == "" {
				arity = 0
			}
		}
		result.Macros = append(result.Macros, MacroFact{
			Name: match[1], QualifiedName: match[1], Body: strings.TrimSpace(match[3]),
			FunctionLike: functionLike, Arity: arity, Line: index + 1,
			Condition: conditionForLine(conditions, index+1),
		})
	}
}

func extractTypeAliases(lang string, lines []string, conditions map[int]string, result *ParseResult) {
	for index, line := range lines {
		lineNumber := index + 1
		condition := conditionForLine(conditions, lineNumber)
		var name, target, parameters, kind string
		switch lang {
		case "cpp":
			if match := cppUsingAliasRE.FindStringSubmatch(line); match != nil {
				name, target, kind = match[1], strings.TrimSpace(match[2]), "using"
			} else if match := cppTypedefAliasRE.FindStringSubmatch(line); match != nil {
				name, target, kind = match[2], strings.TrimSpace(match[1]), "typedef"
			}
		case "rust":
			if match := rustTypeAliasRE.FindStringSubmatch(line); match != nil {
				name, parameters, target, kind = match[1], strings.TrimSpace(match[2]), strings.TrimSpace(match[3]), "type"
			}
		case "csharp":
			if match := csharpUsingAliasRE.FindStringSubmatch(line); match != nil {
				name, target, kind = match[1], strings.TrimSpace(match[2]), "using"
			}
		case "go":
			if match := goTypeAliasRE.FindStringSubmatch(line); match != nil {
				name, target, kind = match[1], strings.TrimSpace(match[2]), "type"
			}
		}
		if name == "" || target == "" {
			continue
		}
		_, owner := variableOwner(result, lineNumber)
		result.Aliases = append(result.Aliases, TypeAliasFact{
			Name: name, QualifiedName: joinQualified(owner, name), Target: target,
			Owner: owner, Kind: kind, TypeParameters: parameters,
			Condition: condition, Line: lineNumber,
		})
	}
}

type conditionFrame struct {
	branches []string
	active   string
}

// sourceConditions records deterministic preprocessor provenance. It does not
// choose a build configuration: mutually exclusive branches remain queryable
// facts instead of being silently discarded.
func sourceConditions(lang string, lines []string) map[int]string {
	result := make(map[int]string)
	if lang != "cpp" {
		return result
	}
	var stack []conditionFrame
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			directive := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
			switch {
			case strings.HasPrefix(directive, "ifdef "):
				value := "defined(" + strings.TrimSpace(strings.TrimPrefix(directive, "ifdef ")) + ")"
				stack = append(stack, conditionFrame{branches: []string{value}, active: value})
			case strings.HasPrefix(directive, "ifndef "):
				value := "!defined(" + strings.TrimSpace(strings.TrimPrefix(directive, "ifndef ")) + ")"
				stack = append(stack, conditionFrame{branches: []string{value}, active: value})
			case strings.HasPrefix(directive, "if "):
				value := strings.TrimSpace(strings.TrimPrefix(directive, "if "))
				stack = append(stack, conditionFrame{branches: []string{value}, active: value})
			case strings.HasPrefix(directive, "elif ") && len(stack) > 0:
				value := strings.TrimSpace(strings.TrimPrefix(directive, "elif "))
				frame := &stack[len(stack)-1]
				frame.active = "!(" + strings.Join(frame.branches, " || ") + ") && (" + value + ")"
				frame.branches = append(frame.branches, value)
			case directive == "else" && len(stack) > 0:
				frame := &stack[len(stack)-1]
				frame.active = "!(" + strings.Join(frame.branches, " || ") + ")"
			case directive == "endif" && len(stack) > 0:
				stack = stack[:len(stack)-1]
			}
		}
		var active []string
		for _, frame := range stack {
			if frame.active != "" {
				active = append(active, "("+frame.active+")")
			}
		}
		if len(active) > 0 {
			result[index+1] = strings.Join(active, " && ")
		}
	}
	return result
}

func conditionForLine(conditions map[int]string, line int) string { return conditions[line] }

func signatureParameterTypes(lang, signature string) string {
	parameters := signatureParameters(lang, signature)
	types := make([]string, 0, len(parameters))
	for _, parameter := range parameters {
		types = append(types, normalizeTypeExpression(parameter.typeName))
	}
	return strings.Join(types, ",")
}

func signatureReturnType(lang string, symbol Symbol) string {
	signature := strings.TrimSpace(symbol.Signature)
	if signature == "" {
		return ""
	}
	if owner := qualifiedOwner(symbol.QualifiedName); owner != "" && shortTypeName(owner) == symbol.Name {
		return shortTypeName(owner)
	}
	open := signatureParameterOpen(lang, signature)
	close := -1
	if open >= 0 {
		close = matchingDelimiter(signature, open, '(', ')')
	}
	switch lang {
	case "rust", "python":
		if close >= 0 {
			tail := strings.TrimSpace(signature[close+1:])
			if arrow := strings.Index(tail, "->"); arrow >= 0 {
				return normalizeReturnExpression(tail[arrow+2:])
			}
		}
	case "go":
		if close >= 0 {
			return normalizeGoResults(strings.TrimSpace(signature[close+1:]))
		}
	default:
		if close >= 0 {
			tail := strings.TrimSpace(signature[close+1:])
			if arrow := strings.Index(tail, "->"); arrow >= 0 {
				return normalizeReturnExpression(tail[arrow+2:])
			}
		}
		prefixEnd := len(signature)
		if open >= 0 {
			prefixEnd = open
		}
		nameIndex := strings.LastIndex(signature[:prefixEnd], symbol.Name)
		if nameIndex >= 0 {
			prefix := strings.TrimSpace(signature[:nameIndex])
			owner := qualifiedOwner(symbol.QualifiedName)
			for _, ownerName := range []string{owner, shortTypeName(owner)} {
				if ownerName != "" {
					prefix = strings.TrimSpace(strings.TrimSuffix(prefix, ownerName+"::"))
				}
			}
			words := strings.Fields(prefix)
			for len(words) > 0 && isFunctionModifier(words[0]) {
				words = words[1:]
			}
			return normalizeTypeExpression(strings.Join(words, " "))
		}
	}
	return ""
}

func normalizeGoResults(value string) string {
	value = strings.TrimSpace(strings.SplitN(value, " where ", 2)[0])
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "(") {
		if close := matchingDelimiter(value, 0, '(', ')'); close > 0 {
			var types []string
			for _, result := range splitTopLevel(value[1:close]) {
				words := strings.Fields(strings.TrimSpace(result))
				if len(words) > 1 {
					result = words[len(words)-1]
				}
				types = append(types, normalizeTypeExpression(result))
			}
			return strings.Join(types, ",")
		}
	}
	return normalizeTypeExpression(strings.Fields(value)[0])
}

func normalizeReturnExpression(value string) string {
	for _, separator := range []string{" where ", " throws ", " {", ";"} {
		if index := strings.Index(value, separator); index >= 0 {
			value = value[:index]
		}
	}
	return normalizeTypeExpression(value)
}

func normalizeTypeExpression(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, ".", "::"))
	for _, prefix := range []string{"const ", "volatile ", "struct ", "class ", "enum ", "ref ", "out ", "in ", "this ", "mut ", "&mut ", "&", "*const ", "*mut ", "? extends ", "? super "} {
		value = strings.TrimSpace(strings.TrimPrefix(value, prefix))
	}
	value = strings.Join(strings.Fields(value), " ")
	return strings.Trim(value, " &")
}

func genericArguments(value string) string {
	open := strings.Index(value, "<")
	if open < 0 {
		return ""
	}
	close := matchingDelimiter(value, open, '<', '>')
	if close < 0 {
		return ""
	}
	return strings.TrimSpace(value[open+1 : close])
}

func signatureModifiers(lang, signature string) string {
	var found []string
	if lang == "csharp" && csharpExtensionRE.MatchString(signature) {
		found = append(found, "extension")
	}
	for _, word := range strings.Fields(strings.NewReplacer("(", " ", ")", " ", "{", " ").Replace(signature)) {
		word = strings.Trim(word, ":")
		if isFunctionModifier(word) || word == "default" || word == "async" || word == "unsafe" || word == "const" {
			found = append(found, word)
		}
	}
	sort.Strings(found)
	return strings.Join(uniqueStrings(found), ",")
}

func isFunctionModifier(word string) bool {
	switch word {
	case "public", "private", "protected", "internal", "static", "extern", "inline", "constexpr", "virtual", "override", "abstract", "final", "sealed", "synchronized", "native", "pub", "fn", "func", "def":
		return true
	}
	return false
}

func semanticIdentity(lang string, symbol Symbol) string {
	kind := symbol.Kind
	if kind == "property" {
		kind = "method"
	}
	return strings.Join([]string{lang, kind, normalizeScope(symbol.QualifiedName), itoa(symbol.Arity), symbol.ParameterTypes}, "|")
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func extractVariableFacts(lang string, lines []string, result *ParseResult) {
	for index, line := range lines {
		lineNumber := index + 1
		var name, typeName string
		switch lang {
		case "cpp":
			if match := cppDeclarationRE.FindStringSubmatch(stripLineComment(line)); match != nil {
				typeName, name = cleanTypeName(match[1]), match[2]
			}
		case "csharp", "java":
			if match := cFamilyDeclarationRE.FindStringSubmatch(stripLineComment(line)); match != nil {
				typeName, name = cleanTypeName(match[1]), match[2]
			}
		case "rust":
			if match := rustLetFactRE.FindStringSubmatch(line); match != nil {
				name, typeName = match[1], cleanTypeName(match[2])
				if typeName == "" {
					typeName = inferredConstructorType(match[3])
				}
			} else if match := rustFieldFactRE.FindStringSubmatch(line); match != nil {
				name, typeName = match[1], cleanTypeName(match[2])
			}
		}
		if name == "" || isDeclarationKeyword(typeName) {
			// A plain assignment may still be a useful alias fact.
		} else {
			kind, owner := variableOwner(result, lineNumber)
			result.Variables = append(result.Variables, VariableFact{
				Name: name, QualifiedName: joinQualified(owner, name), TypeName: typeName,
				Owner: owner, Kind: kind, Line: lineNumber,
			})
		}
		if match := aliasFactRE.FindStringSubmatch(stripLineComment(line)); match != nil && match[1] != match[2] {
			_, owner := variableOwner(result, lineNumber)
			result.Variables = append(result.Variables, VariableFact{Name: match[1], QualifiedName: joinQualified(owner, match[1]), Owner: owner, Kind: "alias", Target: match[2], Line: lineNumber})
		}
	}

	// Parameters are high-value receiver seeds and are less reliably matched by
	// line declaration regexes, especially for generic C#/Java and Rust types.
	for _, function := range result.Functions {
		bounds := signatureGenericBounds(lang, function.Signature)
		for parameter, bound := range bounds {
			result.Variables = append(result.Variables, VariableFact{
				Name: parameter, QualifiedName: joinQualified(function.QualifiedName, parameter),
				TypeName: bound, Owner: function.QualifiedName, Kind: "type_parameter", Line: function.Line,
			})
		}
		for _, parameter := range signatureParameters(lang, function.Signature) {
			result.Variables = append(result.Variables, VariableFact{
				Name: parameter.name, QualifiedName: joinQualified(function.QualifiedName, parameter.name),
				TypeName: parameter.typeName, Owner: function.QualifiedName, Kind: "parameter", Line: function.Line,
			})
		}
	}
}

func signatureGenericBounds(lang, signature string) map[string]string {
	result := make(map[string]string)
	if lang == "rust" || lang == "java" {
		open := strings.Index(signature, "<")
		if open >= 0 {
			if close := matchingDelimiter(signature, open, '<', '>'); close > open {
				for _, raw := range splitTopLevel(signature[open+1 : close]) {
					if lang == "rust" {
						parts := strings.SplitN(raw, ":", 2)
						if len(parts) == 2 {
							result[strings.TrimSpace(parts[0])] = firstTypeBound(parts[1])
						}
					} else {
						parts := strings.SplitN(raw, " extends ", 2)
						if len(parts) == 2 {
							result[strings.TrimSpace(parts[0])] = firstTypeBound(parts[1])
						}
					}
				}
			}
		}
	}
	if lang == "csharp" {
		remaining := signature
		for {
			index := strings.Index(remaining, "where ")
			if index < 0 {
				break
			}
			remaining = remaining[index+len("where "):]
			parts := strings.SplitN(remaining, ":", 2)
			if len(parts) != 2 {
				break
			}
			name := strings.TrimSpace(parts[0])
			result[name] = firstTypeBound(parts[1])
			remaining = parts[1]
		}
	}
	return result
}

func firstTypeBound(value string) string {
	value = strings.TrimSpace(value)
	for _, separator := range []string{"+", ",", " where ", "{"} {
		if index := strings.Index(value, separator); index >= 0 {
			value = value[:index]
		}
	}
	return cleanTypeName(value)
}

func extractCallbackFacts(lang string, lines []string, result *ParseResult) {
	for index, line := range lines {
		lineNumber := index + 1
		if lang == "cpp" {
			for _, match := range cppFunctionPointerRE.FindAllStringSubmatch(line, -1) {
				_, owner := variableOwner(result, lineNumber)
				target := ""
				if initializer := callbackInitializerRE.FindStringSubmatch(line); initializer != nil {
					target = normalizeCallee(initializer[1])
				}
				result.Variables = append(result.Variables, VariableFact{Name: match[1], QualifiedName: joinQualified(owner, match[1]), TypeName: "function", Owner: owner, Kind: "callback", Target: target, Line: lineNumber})
			}
		}
		if lang == "rust" {
			if match := rustFunctionValueRE.FindStringSubmatch(line); match != nil {
				_, owner := variableOwner(result, lineNumber)
				result.Variables = append(result.Variables, VariableFact{Name: match[1], QualifiedName: joinQualified(owner, match[1]), TypeName: "function", Owner: owner, Kind: "callback", Target: normalizeCallee(match[3]), Line: lineNumber})
			}
		}
		if lang == "java" {
			if match := javaMethodReferenceRE.FindStringSubmatch(line); match != nil {
				_, owner := variableOwner(result, lineNumber)
				target := normalizeCallee(match[2] + "::" + match[3])
				result.Variables = append(result.Variables, VariableFact{Name: match[1], QualifiedName: joinQualified(owner, match[1]), TypeName: "method_reference", Owner: owner, Kind: "callback", Target: target, Line: lineNumber})
			}
		}
		if lang == "csharp" {
			if match := csharpDelegateRE.FindStringSubmatch(line); match != nil {
				_, owner := variableOwner(result, lineNumber)
				result.Variables = append(result.Variables, VariableFact{Name: match[1], QualifiedName: joinQualified(owner, match[1]), TypeName: "delegate", Owner: owner, Kind: "callback", Target: normalizeCallee(match[2]), Line: lineNumber})
			}
		}
		if name, arity, ok := sourceLambdaAssignment(lang, line); ok {
			_, owner := variableOwner(result, lineNumber)
			target := joinQualified(owner, "lambda@"+itoa(lineNumber))
			endLine := braceBlockEnd(lines, lineNumber, 0)
			result.Functions = append(result.Functions, Symbol{Capture: "function", NodeType: "lambda", Name: "lambda@" + itoa(lineNumber), QualifiedName: target, Kind: "function", Scope: owner, Line: lineNumber, EndLine: endLine, Arity: arity})
			result.Variables = append(result.Variables, VariableFact{Name: name, QualifiedName: joinQualified(owner, name), TypeName: "lambda", Owner: owner, Kind: "callback", Target: target, Line: lineNumber})
			for callIndex := range result.Calls {
				call := &result.Calls[callIndex]
				if call.Line >= lineNumber && call.Line <= endLine && call.Name != name {
					call.Scope = target
				}
			}
		}
		for _, match := range callbackAssignmentRE.FindAllStringSubmatch(line, -1) {
			for i := range result.Variables {
				if result.Variables[i].Name == match[1] && (result.Variables[i].Kind == "callback" || result.Variables[i].TypeName == "function") {
					result.Variables[i].Kind = "callback"
					result.Variables[i].Target = normalizeCallee(match[2])
				}
			}
		}
	}
}

func sourceLambdaAssignment(lang, line string) (string, int, bool) {
	var match []string
	var parameters string
	switch lang {
	case "cpp":
		match = lambdaAssignmentRE.FindStringSubmatch(line)
		if match != nil {
			return match[1], lambdaArity(line), true
		}
	case "rust":
		match = rustClosureRE.FindStringSubmatch(line)
		if match != nil {
			parameters = match[2]
		}
	case "csharp":
		match = csharpLambdaRE.FindStringSubmatch(line)
		if match != nil {
			parameters = match[2]
			if parameters == "" {
				parameters = match[3]
			}
		}
	case "java":
		match = javaLambdaRE.FindStringSubmatch(line)
		if match != nil {
			parameters = match[2]
		}
	}
	if match == nil {
		return "", -1, false
	}
	parameters = strings.TrimSpace(parameters)
	if parameters == "" {
		return match[1], 0, true
	}
	return match[1], len(splitTopLevel(parameters)), true
}

func variableOwner(result *ParseResult, line int) (string, string) {
	if function := smallestContaining(result.Functions, line, line); function != nil {
		return "local", function.QualifiedName
	}
	if typ := smallestContaining(result.Classes, line, line); typ != nil {
		return "field", typ.QualifiedName
	}
	return "global", ""
}

type sourceParameter struct{ name, typeName string }

func signatureParameters(lang, signature string) []sourceParameter {
	open := signatureParameterOpen(lang, signature)
	if open < 0 {
		return nil
	}
	close := matchingDelimiter(signature, open, '(', ')')
	if close < 0 {
		return nil
	}
	var result []sourceParameter
	for _, raw := range splitTopLevel(signature[open+1 : close]) {
		raw = strings.TrimSpace(strings.SplitN(raw, "=", 2)[0])
		if raw == "" || raw == "void" || raw == "self" || raw == "&self" || raw == "&mut self" {
			continue
		}
		if lang == "rust" {
			parts := strings.SplitN(raw, ":", 2)
			if len(parts) == 2 {
				result = append(result, sourceParameter{name: strings.TrimSpace(strings.TrimPrefix(parts[0], "mut ")), typeName: cleanTypeName(parts[1])})
			}
			continue
		}
		words := strings.Fields(raw)
		if len(words) < 2 {
			continue
		}
		name := strings.Trim(words[len(words)-1], "*&[] ")
		typeName := cleanTypeName(strings.Join(words[:len(words)-1], " "))
		if name != "" && typeName != "" {
			result = append(result, sourceParameter{name: name, typeName: typeName})
		}
	}
	return result
}

func signatureArity(lang, signature string) int {
	open := signatureParameterOpen(lang, signature)
	if open < 0 {
		return -1
	}
	close := matchingDelimiter(signature, open, '(', ')')
	if close < 0 {
		return -1
	}
	params := splitTopLevel(signature[open+1 : close])
	if len(params) == 1 && (strings.TrimSpace(params[0]) == "" || strings.TrimSpace(params[0]) == "void") {
		return 0
	}
	count := 0
	for _, parameter := range params {
		parameter = strings.TrimSpace(parameter)
		if lang == "rust" && (parameter == "self" || parameter == "&self" || parameter == "&mut self" || parameter == "mut self") {
			continue
		}
		if parameter != "" && parameter != "..." {
			count++
		}
	}
	return count
}

func signatureParameterOpen(lang, signature string) int {
	open := strings.Index(signature, "(")
	if lang != "go" || open < 0 {
		return open
	}
	// A Go method signature starts with func (receiver) Name(params). The
	// receiver is not part of the explicit call arity.
	prefix := strings.TrimSpace(signature[:open])
	if prefix != "func" {
		return open
	}
	close := matchingDelimiter(signature, open, '(', ')')
	if close < 0 {
		return open
	}
	next := strings.Index(signature[close+1:], "(")
	if next < 0 {
		return open
	}
	return close + 1 + next
}

func callArgumentsAt(source string, lines []string, line, col int) (string, bool) {
	return callArgumentsAtOffset(source, lines, line, col, "")
}

func callArgumentsForSymbol(source string, lines []string, call Symbol) (string, bool) {
	return callArgumentsAtOffset(source, lines, call.Line, call.Col, call.RawText)
}

func callArgumentsAtOffset(source string, lines []string, line, col int, rawCallee string) (string, bool) {
	if line <= 0 || line > len(lines) {
		return "", false
	}
	offset := 0
	for i := 0; i < line-1; i++ {
		offset += len(lines[i]) + 1
	}
	offset += max(col, 0)
	if offset >= len(source) {
		return "", false
	}
	tail := source[offset:]
	openRelative := -1
	if rawCallee != "" {
		if rawIndex := strings.Index(tail, rawCallee); rawIndex >= 0 {
			openRelative = rawIndex + len(rawCallee)
			for openRelative < len(tail) && (tail[openRelative] == ' ' || tail[openRelative] == '\t') {
				openRelative++
			}
			if openRelative >= len(tail) || tail[openRelative] != '(' {
				openRelative = -1
			}
		}
	}
	if openRelative < 0 {
		openRelative = strings.Index(tail, "(")
	}
	if openRelative < 0 || openRelative > 1024 {
		return "", false
	}
	open := offset + openRelative
	close := matchingDelimiter(source, open, '(', ')')
	if close < 0 {
		return "", false
	}
	return source[open+1 : close], true
}

func splitTopLevel(value string) []string {
	var parts []string
	start := 0
	depth := 0
	quote := rune(0)
	escaped := false
	for index, char := range value {
		if quote != 0 {
			if escaped {
				escaped = false
			} else if char == '\\' {
				escaped = true
			} else if char == quote {
				quote = 0
			}
			continue
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			continue
		}
		switch char {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}', '>':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(value[start:index]))
				start = index + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(value[start:]))
	return parts
}

func matchingDelimiter(value string, open int, left, right rune) int {
	depth := 0
	quote := rune(0)
	escaped := false
	for index, char := range value[open:] {
		if quote != 0 {
			if escaped {
				escaped = false
			} else if char == '\\' {
				escaped = true
			} else if char == quote {
				quote = 0
			}
			continue
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			continue
		}
		if char == left {
			depth++
		} else if char == right {
			depth--
			if depth == 0 {
				return open + index
			}
		}
	}
	return -1
}

func inferArgumentTypes(arguments []string) string {
	types := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		argument = strings.TrimSpace(argument)
		typeName := "unknown"
		switch {
		case argument == "true" || argument == "false":
			typeName = "bool"
		case argument == "nullptr" || argument == "NULL" || argument == "null" || argument == "nil":
			typeName = "null"
		case strings.HasPrefix(argument, `"`) || strings.HasPrefix(argument, `L"`):
			typeName = "string"
		case strings.HasPrefix(argument, "'"):
			typeName = "char"
		case looksNumeric(argument):
			if strings.ContainsAny(argument, ".eE") {
				typeName = "float"
			} else {
				typeName = "int"
			}
		}
		types = append(types, typeName)
	}
	return strings.Join(types, ",")
}

func looksNumeric(value string) bool {
	value = strings.TrimLeft(value, "+-")
	if value == "" {
		return false
	}
	for _, char := range value {
		if !unicode.IsDigit(char) && !strings.ContainsRune(".xXaAbBcCdDeEfFuUlL", char) {
			return false
		}
	}
	return true
}

func cleanTypeName(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, ".", "::")
	for _, prefix := range []string{"const ", "volatile ", "static ", "struct ", "class ", "enum ", "ref ", "out ", "in ", "mut ", "&mut ", "&"} {
		value = strings.TrimSpace(strings.TrimPrefix(value, prefix))
	}
	value = strings.Trim(value, "*&?[] ")
	if index := strings.Index(value, "<"); index >= 0 {
		value = value[:index]
	}
	return normalizeScope(strings.TrimSpace(value))
}

func inferredConstructorType(expression string) string {
	expression = strings.TrimSpace(strings.TrimPrefix(expression, "new "))
	for index, char := range expression {
		if char == '(' || char == '{' || unicode.IsSpace(char) {
			return cleanTypeName(expression[:index])
		}
	}
	return ""
}

func stripLineComment(line string) string {
	if index := strings.Index(line, "//"); index >= 0 {
		return line[:index]
	}
	return line
}

func isDeclarationKeyword(typeName string) bool {
	switch typeName {
	case "return", "if", "for", "while", "switch", "case", "else", "using", "namespace", "package", "import", "typedef":
		return true
	}
	return false
}

func lambdaArity(line string) int {
	closeCapture := strings.Index(line, "]")
	if closeCapture < 0 {
		return -1
	}
	open := strings.Index(line[closeCapture+1:], "(")
	if open < 0 {
		return 0
	}
	open += closeCapture + 1
	close := matchingDelimiter(line, open, '(', ')')
	if close < 0 {
		return -1
	}
	args := strings.TrimSpace(line[open+1 : close])
	if args == "" {
		return 0
	}
	return len(splitTopLevel(args))
}
