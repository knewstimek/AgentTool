package codegraph

import (
	"database/sql"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
)

const maxCandidatesPerCall = 16

type semanticCall struct {
	id, fileID                         int64
	name, qualified, receiver, raw     string
	caller, path, language, sourceRoot string
	argumentTypes                      string
	argumentExpressions                string
	receiverType, condition            string
	arity, line                        int
}

type semanticSymbol struct {
	id, semanticID, fileID     int64
	name, qualified, kind      string
	path, signature, language  string
	parameterTypes, returnType string
	modifiers                  string
	arity                      int
	occurrencePaths            []string
	occurrenceFileIDs          []int64
	occurrenceRoots            []string
}

type semanticVariable struct {
	fileID                      int64
	name, typeName, owner, kind string
	target, path                string
	line                        int
}

type semanticAlias struct {
	fileID                                                 int64
	name, qualified, target, owner, kind, parameters, path string
	line                                                   int
}

type variableIndex struct {
	locals    map[string][]semanticVariable
	fields    map[string][]semanticVariable
	globals   map[string][]semanticVariable
	callbacks map[string][]semanticVariable
}

type rankedTarget struct {
	symbol     semanticSymbol
	confidence float64
	basis      string
}

type symbolOccurrence struct {
	id, fileID                      int64
	name, qualified, kind, language string
	parameterTypes, returnType      string
	modifiers, signature, path      string
	arity, line, endLine            int
}

// rebuildSemanticSymbols makes declaration/definition identity explicit.
// Existing symbol rows remain source occurrences for backwards-compatible
// queries, while candidate resolution operates on one representative per key.
func rebuildSemanticSymbols(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT s.id, s.file_id, s.name, s.qualified_name, s.kind,
		s.arity, s.parameter_types, s.return_type, s.modifiers, s.signature,
		s.line, s.end_line, f.path, f.language
		FROM symbols s JOIN files f ON f.id=s.file_id
		ORDER BY f.language, s.qualified_name, s.kind, s.arity, s.parameter_types, f.path, s.line`)
	if err != nil {
		return err
	}
	var occurrences []symbolOccurrence
	for rows.Next() {
		var occurrence symbolOccurrence
		if err := rows.Scan(&occurrence.id, &occurrence.fileID, &occurrence.name,
			&occurrence.qualified, &occurrence.kind, &occurrence.arity,
			&occurrence.parameterTypes, &occurrence.returnType, &occurrence.modifiers,
			&occurrence.signature, &occurrence.line, &occurrence.endLine,
			&occurrence.path, &occurrence.language); err != nil {
			rows.Close()
			return err
		}
		occurrences = append(occurrences, occurrence)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM symbol_occurrences"); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM semantic_symbols"); err != nil {
		return err
	}

	type semanticGroup struct {
		key, name, qualified, kind, language  string
		parameterTypes, returnType, modifiers string
		arity                                 int
		occurrences                           []symbolOccurrence
	}
	groups := make(map[string]*semanticGroup)
	var keys []string
	for _, occurrence := range occurrences {
		key := semanticKeyForOccurrence(occurrence)
		if _, err := tx.Exec("UPDATE symbols SET semantic_key=? WHERE id=?", key, occurrence.id); err != nil {
			return err
		}
		group := groups[key]
		if group == nil {
			group = &semanticGroup{key: key, name: occurrence.name, qualified: occurrence.qualified,
				kind: occurrence.kind, language: occurrence.language, arity: occurrence.arity,
				parameterTypes: occurrence.parameterTypes}
			groups[key] = group
			keys = append(keys, key)
		}
		group.occurrences = append(group.occurrences, occurrence)
		if betterTypeSummary(occurrence.returnType, group.returnType) {
			group.returnType = occurrence.returnType
		}
		group.modifiers = mergeCSV(group.modifiers, occurrence.modifiers)
	}
	sort.Strings(keys)
	insertSemantic, err := tx.Prepare(`INSERT INTO semantic_symbols
		(semantic_key,name,qualified_name,kind,language,arity,parameter_types,return_type,modifiers)
		VALUES (?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer insertSemantic.Close()
	insertOccurrence, err := tx.Prepare("INSERT INTO symbol_occurrences(semantic_id,symbol_id,role) VALUES (?,?,?)")
	if err != nil {
		return err
	}
	defer insertOccurrence.Close()
	for _, key := range keys {
		group := groups[key]
		result, err := insertSemantic.Exec(group.key, group.name, group.qualified, group.kind,
			group.language, group.arity, group.parameterTypes, group.returnType, group.modifiers)
		if err != nil {
			return err
		}
		semanticID, err := result.LastInsertId()
		if err != nil {
			return err
		}
		for _, occurrence := range group.occurrences {
			role := "declaration"
			if occurrence.endLine > occurrence.line || strings.Contains(occurrence.signature, "{") {
				role = "definition"
			}
			if _, err := insertOccurrence.Exec(semanticID, occurrence.id, role); err != nil {
				return err
			}
		}
	}
	return nil
}

func semanticKeyForOccurrence(occurrence symbolOccurrence) string {
	kind := occurrence.kind
	if kind == "property" {
		kind = "method"
	}
	return strings.Join([]string{occurrence.language, kind, normalizeScope(occurrence.qualified),
		fmt.Sprintf("%d", occurrence.arity), occurrence.parameterTypes}, "|")
}

func betterTypeSummary(candidate, current string) bool {
	candidate, current = strings.TrimSpace(candidate), strings.TrimSpace(current)
	if candidate == "" {
		return false
	}
	if current == "" {
		return true
	}
	if len(candidate) != len(current) {
		return len(candidate) > len(current)
	}
	return candidate < current
}

func mergeCSV(left, right string) string {
	values := strings.FieldsFunc(left+","+right, func(r rune) bool { return r == ',' })
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
	}
	sort.Strings(values)
	return strings.Join(uniqueStrings(values), ",")
}

type indexedFile struct {
	id   int64
	path string
}

type sourceInclude struct {
	id, fileID          int64
	included, condition string
}

func rebuildIncludeEdges(tx *sql.Tx) error {
	fileRows, err := tx.Query("SELECT id,path FROM files ORDER BY path")
	if err != nil {
		return err
	}
	var files []indexedFile
	byPath := make(map[string]indexedFile)
	byBase := make(map[string][]indexedFile)
	for fileRows.Next() {
		var file indexedFile
		if err := fileRows.Scan(&file.id, &file.path); err != nil {
			fileRows.Close()
			return err
		}
		files = append(files, file)
		byPath[normalizedFSPath(file.path)] = file
		base := strings.ToLower(filepath.Base(file.path))
		byBase[base] = append(byBase[base], file)
	}
	if err := fileRows.Close(); err != nil {
		return err
	}
	includeRows, err := tx.Query(`SELECT i.id,i.file_id,i.included,COALESCE(c.expression,i.condition)
		FROM includes i LEFT JOIN conditions c ON c.id=i.condition_id ORDER BY i.file_id,i.line,i.id`)
	if err != nil {
		return err
	}
	var includes []sourceInclude
	for includeRows.Next() {
		var include sourceInclude
		if err := includeRows.Scan(&include.id, &include.fileID, &include.included, &include.condition); err != nil {
			includeRows.Close()
			return err
		}
		includes = append(includes, include)
	}
	if err := includeRows.Close(); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM include_edges"); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE includes SET resolved_file_id=NULL"); err != nil {
		return err
	}
	direct := make(map[int64][]int64)
	directCondition := make(map[[2]int64]string)
	pathByID := make(map[int64]string, len(files))
	for _, file := range files {
		pathByID[file.id] = file.path
	}
	for _, include := range includes {
		sourcePath := pathByID[include.fileID]
		included := strings.Trim(strings.TrimSpace(include.included), `\"<>`)
		if included == "" {
			continue
		}
		var candidates []indexedFile
		exact := normalizedFSPath(filepath.Join(filepath.Dir(sourcePath), filepath.FromSlash(included)))
		if file, ok := byPath[exact]; ok {
			candidates = append(candidates, file)
		} else {
			candidates = append(candidates, byBase[strings.ToLower(filepath.Base(included))]...)
		}
		bestID, bestScore, bestPath := int64(0), -1.0, ""
		normalizedIncluded := strings.ToLower(filepath.ToSlash(filepath.Clean(included)))
		for _, candidate := range candidates {
			candidateSlash := strings.ToLower(filepath.ToSlash(candidate.path))
			if !strings.HasSuffix(candidateSlash, normalizedIncluded) && filepath.Base(candidate.path) != filepath.Base(included) {
				continue
			}
			score := directoryProximity(sourcePath, candidate.path)
			if normalizedFSPath(candidate.path) == exact {
				score += 10
			}
			if score > bestScore || score == bestScore && candidate.path < bestPath {
				bestID, bestScore, bestPath = candidate.id, score, candidate.path
			}
		}
		if bestID == 0 {
			continue
		}
		if _, err := tx.Exec("UPDATE includes SET resolved_file_id=? WHERE id=?", bestID, include.id); err != nil {
			return err
		}
		direct[include.fileID] = append(direct[include.fileID], bestID)
		directCondition[[2]int64{include.fileID, bestID}] = include.condition
	}
	insertEdge, err := tx.Prepare("INSERT INTO include_edges(file_id,included_file_id,distance,condition_id) VALUES (?,?,?,?)")
	if err != nil {
		return err
	}
	defer insertEdge.Close()
	conditionCache := make(map[string]any)
	for _, source := range files {
		distance := map[int64]int{source.id: 0}
		condition := make(map[int64]string)
		queue := []int64{source.id}
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			for _, next := range direct[current] {
				candidateDistance := distance[current] + 1
				if prior, ok := distance[next]; ok && prior <= candidateDistance {
					continue
				}
				distance[next] = candidateDistance
				condition[next] = joinConditions(condition[current], directCondition[[2]int64{current, next}])
				queue = append(queue, next)
			}
		}
		var targets []int64
		for target := range distance {
			if target != source.id {
				targets = append(targets, target)
			}
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })
		for _, target := range targets {
			conditionID, err := internCondition(tx, conditionCache, condition[target])
			if err != nil {
				return err
			}
			if _, err := insertEdge.Exec(source.id, target, distance[target], conditionID); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizedFSPath(path string) string {
	return strings.ToLower(filepath.Clean(path))
}

func joinConditions(left, right string) string {
	if left == "" {
		return right
	}
	if right == "" || right == left {
		return left
	}
	return "(" + left + ") && (" + right + ")"
}

// resolveCallCandidates is the project-wide semantic pass. It deliberately
// keeps uncertain relations set-valued while assigning non-runtime constructs
// their own target kind so they no longer inflate the true unresolved rate.
func resolveCallCandidates(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM dispatch_edges"); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM inheritance WHERE relation_kind LIKE 'inferred_%'"); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM call_candidates"); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM macro_uses"); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM callback_edges"); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE calls SET resolution='unresolved', confidence=0.20, target_kind='unresolved'"); err != nil {
		return err
	}
	if err := rebuildIncludeEdges(tx); err != nil {
		return err
	}
	if err := rebuildSemanticSymbols(tx); err != nil {
		return err
	}

	calls, err := loadSemanticCalls(tx)
	if err != nil {
		return err
	}
	symbols, byName, err := loadSemanticSymbols(tx)
	if err != nil {
		return err
	}
	knownTypes := make(map[string]bool)
	knownTypePaths := make(map[string][]string)
	knownTypeRoots := make(map[string][]string)
	for _, symbol := range symbols {
		if symbol.kind == "method" {
			owner := shortTypeName(qualifiedOwner(symbol.qualified))
			knownTypes[owner] = true
			knownTypePaths[owner] = append(knownTypePaths[owner], symbol.occurrencePaths...)
			knownTypeRoots[owner] = append(knownTypeRoots[owner], symbol.occurrenceRoots...)
		} else if symbol.kind != "function" && symbol.kind != "property" {
			name := shortTypeName(symbol.qualified)
			knownTypes[name] = true
			knownTypePaths[name] = append(knownTypePaths[name], symbol.occurrencePaths...)
			knownTypeRoots[name] = append(knownTypeRoots[name], symbol.occurrenceRoots...)
		}
	}
	variables, err := loadSemanticVariables(tx)
	if err != nil {
		return err
	}
	variableFacts := indexSemanticVariables(variables)
	aliases, err := loadSemanticAliases(tx)
	if err != nil {
		return err
	}
	macros, err := loadMacroNames(tx)
	if err != nil {
		return err
	}
	includes, err := loadIncludeFacts(tx)
	if err != nil {
		return err
	}
	parents, err := loadParentTypes(tx)
	if err != nil {
		return err
	}
	sourceParents := cloneParentMap(parents)
	inferGoInterfaceImplementations(symbols, parents)
	expandBlanketImplementations(parents)
	inferRustDerefParents(aliases, parents)
	if err := persistInferredTypeRelations(tx, symbols, sourceParents, parents); err != nil {
		return err
	}
	for child := range parents {
		knownTypes[shortTypeName(child)] = true
	}

	insertCandidate, err := tx.Prepare("INSERT OR IGNORE INTO call_candidates(call_id, symbol_id, confidence, basis, semantic_id, evidence) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer insertCandidate.Close()
	insertDispatch, err := tx.Prepare(`INSERT OR IGNORE INTO dispatch_edges
		(call_id,semantic_id,dispatch_kind,confidence,basis) VALUES (?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer insertDispatch.Close()

	for _, call := range calls {
		if call.language == "rust" && strings.HasSuffix(strings.TrimSpace(call.raw), "!") {
			if macro, ok := matchingMacro(macros[call.name], call, includes[call.fileID]); ok {
				if _, err := tx.Exec("UPDATE calls SET callee_qualified_name=?, resolution='classified', confidence=1, target_kind='macro' WHERE id=?", macro.qualified, call.id); err != nil {
					return err
				}
				if _, err := tx.Exec("INSERT INTO macro_uses(call_id, macro_id, name) VALUES (?, ?, ?)", call.id, macro.id, call.name); err != nil {
					return err
				}
			} else {
				if _, err := tx.Exec("UPDATE calls SET resolution='classified', confidence=0.95, target_kind='macro' WHERE id=?", call.id); err != nil {
					return err
				}
				if _, err := tx.Exec("INSERT INTO macro_uses(call_id, macro_id, name) VALUES (?, NULL, ?)", call.id, call.name); err != nil {
					return err
				}
			}
			continue
		}
		if isLanguageConstructCall(call) {
			if _, err := tx.Exec("UPDATE calls SET resolution='classified', confidence=1, target_kind='external' WHERE id=?", call.id); err != nil {
				return err
			}
			continue
		}
		if macro, ok := matchingMacro(macros[call.name], call, includes[call.fileID]); ok {
			if _, err := tx.Exec("UPDATE calls SET callee_qualified_name=?, resolution='classified', confidence=1, target_kind='macro' WHERE id=?", macro.qualified, call.id); err != nil {
				return err
			}
			if _, err := tx.Exec("INSERT INTO macro_uses(call_id, macro_id, name) VALUES (?, ?, ?)", call.id, macro.id, call.name); err != nil {
				return err
			}
			continue
		}
		if wellKnownExternalMacros[call.name] {
			if _, err := tx.Exec("UPDATE calls SET resolution='classified', confidence=0.90, target_kind='macro' WHERE id=?", call.id); err != nil {
				return err
			}
			if _, err := tx.Exec("INSERT INTO macro_uses(call_id, macro_id, name) VALUES (?, NULL, ?)", call.id, call.name); err != nil {
				return err
			}
			continue
		}

		if callback, ok := lookupCallback(call, variableFacts); ok {
			qualified := callback.target
			confidence := 0.90
			resolution := "classified"
			var targetID any
			if target := uniqueQualifiedSymbol(symbols, callback.target); target != nil {
				qualified = target.qualified
				targetID = target.id
				confidence = 1
				resolution = "exact"
				if _, err := insertCandidate.Exec(call.id, target.id, confidence, "callback-target", target.semanticID, ""); err != nil {
					return err
				}
			}
			if qualified == "" {
				qualified = callback.name
			}
			if _, err := tx.Exec("UPDATE calls SET callee_qualified_name=?, resolution=?, confidence=?, target_kind='callback' WHERE id=?", qualified, resolution, confidence, call.id); err != nil {
				return err
			}
			if _, err := tx.Exec("INSERT INTO callback_edges(call_id, symbol_id, target) VALUES (?, ?, ?)", call.id, targetID, qualified); err != nil {
				return err
			}
			continue
		}

		receiverType := resolveReceiverType(call, variableFacts, aliases, byName, parents)
		call.argumentTypes = resolveProjectArgumentTypes(call, variableFacts, aliases, byName, parents)
		if _, err := tx.Exec("UPDATE calls SET receiver_type=?, argument_types=? WHERE id=?", receiverType, call.argumentTypes, call.id); err != nil {
			return err
		}
		candidates := rankSemanticCandidates(call, receiverType, byName[call.name], includes, parents)
		if len(candidates) > maxCandidatesPerCall {
			candidates = candidates[:maxCandidatesPerCall]
		}
		for _, candidate := range candidates {
			if _, err := insertCandidate.Exec(call.id, candidate.symbol.id, candidate.confidence, candidate.basis, candidate.symbol.semanticID, ""); err != nil {
				return err
			}
		}
		if len(candidates) > 0 {
			resolution := "candidate"
			qualified := call.qualified
			uniqueBest := len(candidates) == 1 || confidenceLogOdds(candidates[0].confidence)-confidenceLogOdds(candidates[1].confidence) > 0.35
			if candidates[0].confidence >= 0.82 && uniqueBest {
				resolution = "exact"
				qualified = candidates[0].symbol.qualified
			}
			if _, err := tx.Exec("UPDATE calls SET callee_qualified_name=?, resolution=?, confidence=?, target_kind='internal' WHERE id=?", qualified, resolution, candidates[0].confidence, call.id); err != nil {
				return err
			}
			for _, dispatch := range dynamicDispatchTargets(call, receiverType, candidates[0].symbol, byName[call.name], byName, parents) {
				if _, err := insertDispatch.Exec(call.id, dispatch.symbol.semanticID, dispatch.basis, dispatch.confidence, dispatch.basis); err != nil {
					return err
				}
			}
			continue
		}
		if looksLikeMacroName(call.name) {
			if _, err := tx.Exec("UPDATE calls SET resolution='classified', confidence=0.75, target_kind='macro' WHERE id=?", call.id); err != nil {
				return err
			}
			if _, err := tx.Exec("INSERT INTO macro_uses(call_id, macro_id, name) VALUES (?, NULL, ?)", call.id, call.name); err != nil {
				return err
			}
			continue
		}

		if isExternalCall(call, includes[call.fileID], receiverType, knownTypes, knownTypePaths, knownTypeRoots) {
			qualified := call.qualified
			if receiverType != "" {
				qualified = joinQualified(receiverType, call.name)
			}
			if _, err := tx.Exec("UPDATE calls SET callee_qualified_name=?, resolution='classified', confidence=0.90, target_kind='external' WHERE id=?", qualified, call.id); err != nil {
				return err
			}
		}
	}
	if err := removeUnusedConditions(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func removeUnusedConditions(tx *sql.Tx) error {
	_, err := tx.Exec(`DELETE FROM conditions AS candidate
		WHERE NOT EXISTS (SELECT 1 FROM symbols WHERE condition_id=candidate.id)
		  AND NOT EXISTS (SELECT 1 FROM calls WHERE condition_id=candidate.id)
		  AND NOT EXISTS (SELECT 1 FROM variables WHERE condition_id=candidate.id)
		  AND NOT EXISTS (SELECT 1 FROM includes WHERE condition_id=candidate.id)
		  AND NOT EXISTS (SELECT 1 FROM macros WHERE condition_id=candidate.id)
		  AND NOT EXISTS (SELECT 1 FROM type_aliases WHERE condition_id=candidate.id)
		  AND NOT EXISTS (SELECT 1 FROM include_edges WHERE condition_id=candidate.id)`)
	return err
}

func loadSemanticCalls(tx *sql.Tx) ([]semanticCall, error) {
	rows, err := tx.Query(`SELECT c.id, c.caller_file_id, c.callee_name, c.callee_qualified_name,
		c.receiver, c.raw_text, c.caller_qualified_name, c.arity, c.caller_line, c.argument_types, c.argument_expressions,
		c.receiver_type, COALESCE(condition.expression,c.condition), f.path, f.language, f.source_root
		FROM calls c JOIN files f ON f.id=c.caller_file_id
		LEFT JOIN conditions condition ON condition.id=c.condition_id
		ORDER BY f.path,c.caller_line,c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []semanticCall
	for rows.Next() {
		var call semanticCall
		if err := rows.Scan(&call.id, &call.fileID, &call.name, &call.qualified, &call.receiver, &call.raw, &call.caller, &call.arity, &call.line, &call.argumentTypes, &call.argumentExpressions, &call.receiverType, &call.condition, &call.path, &call.language, &call.sourceRoot); err != nil {
			return nil, err
		}
		result = append(result, call)
	}
	return result, rows.Err()
}

func loadSemanticSymbols(tx *sql.Tx) ([]semanticSymbol, map[string][]semanticSymbol, error) {
	rows, err := tx.Query(`SELECT representative.symbol_id, ss.id, s.file_id, ss.name,
		ss.qualified_name, ss.kind, ss.arity, s.signature, f.path, ss.language,
		ss.parameter_types, ss.return_type, ss.modifiers
		FROM semantic_symbols ss
		JOIN (
			SELECT ranked.semantic_id, ranked.symbol_id FROM (
				SELECT so.semantic_id, so.symbol_id,
				       ROW_NUMBER() OVER (PARTITION BY so.semantic_id ORDER BY
				           CASE so.role WHEN 'definition' THEN 0 ELSE 1 END,
				           occurrence_file.path, occurrence.line, occurrence.id) AS position
				FROM symbol_occurrences so
				JOIN symbols occurrence ON occurrence.id=so.symbol_id
				JOIN files occurrence_file ON occurrence_file.id=occurrence.file_id
			) ranked WHERE ranked.position=1
		) representative ON representative.semantic_id=ss.id
		JOIN symbols s ON s.id=representative.symbol_id
		JOIN files f ON f.id=s.file_id
		WHERE ss.kind IN ('function','method','property','class','struct','record','type','enum','interface','trait')
		ORDER BY ss.semantic_key`)
	if err != nil {
		return nil, nil, err
	}
	var result []semanticSymbol
	byName := make(map[string][]semanticSymbol)
	bySemanticID := make(map[int64]int)
	for rows.Next() {
		var symbol semanticSymbol
		if err := rows.Scan(&symbol.id, &symbol.semanticID, &symbol.fileID, &symbol.name, &symbol.qualified, &symbol.kind, &symbol.arity, &symbol.signature, &symbol.path, &symbol.language, &symbol.parameterTypes, &symbol.returnType, &symbol.modifiers); err != nil {
			return nil, nil, err
		}
		bySemanticID[symbol.semanticID] = len(result)
		result = append(result, symbol)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	occurrences, err := tx.Query(`SELECT so.semantic_id,s.file_id,f.path,f.source_root
		FROM symbol_occurrences so JOIN symbols s ON s.id=so.symbol_id
		JOIN files f ON f.id=s.file_id ORDER BY so.semantic_id,f.path,s.line,s.id`)
	if err != nil {
		return nil, nil, err
	}
	for occurrences.Next() {
		var semanticID, fileID int64
		var path, sourceRoot string
		if err := occurrences.Scan(&semanticID, &fileID, &path, &sourceRoot); err != nil {
			occurrences.Close()
			return nil, nil, err
		}
		if index, ok := bySemanticID[semanticID]; ok {
			result[index].occurrenceFileIDs = append(result[index].occurrenceFileIDs, fileID)
			result[index].occurrencePaths = append(result[index].occurrencePaths, path)
			result[index].occurrenceRoots = append(result[index].occurrenceRoots, sourceRoot)
		}
	}
	if err := occurrences.Close(); err != nil {
		return nil, nil, err
	}
	for _, symbol := range result {
		byName[symbol.name] = append(byName[symbol.name], symbol)
	}
	return result, byName, nil
}

func loadSemanticVariables(tx *sql.Tx) ([]semanticVariable, error) {
	rows, err := tx.Query(`SELECT v.file_id,v.name,v.type_name,v.owner,v.kind,v.target,v.line,f.path
		FROM variables v JOIN files f ON f.id=v.file_id ORDER BY f.path,v.line,v.name,v.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []semanticVariable
	for rows.Next() {
		var variable semanticVariable
		if err := rows.Scan(&variable.fileID, &variable.name, &variable.typeName, &variable.owner, &variable.kind, &variable.target, &variable.line, &variable.path); err != nil {
			return nil, err
		}
		result = append(result, variable)
	}
	return result, rows.Err()
}

func loadSemanticAliases(tx *sql.Tx) (map[string][]semanticAlias, error) {
	rows, err := tx.Query(`SELECT a.file_id,a.name,a.qualified_name,a.target,a.owner,a.kind,a.type_parameters,a.line,f.path
		FROM type_aliases a JOIN files f ON f.id=a.file_id ORDER BY a.name,f.path,a.line,a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][]semanticAlias)
	for rows.Next() {
		var alias semanticAlias
		if err := rows.Scan(&alias.fileID, &alias.name, &alias.qualified, &alias.target,
			&alias.owner, &alias.kind, &alias.parameters, &alias.line, &alias.path); err != nil {
			return nil, err
		}
		result[shortTypeName(alias.name)] = append(result[shortTypeName(alias.name)], alias)
		if alias.name == "Target" {
			owner := strings.TrimSpace(alias.owner)
			if marker := strings.Index(owner, "Deref for "); marker >= 0 {
				wrapper := shortTypeName(owner[marker+len("Deref for "):])
				if wrapper != "" {
					result["@deref:"+wrapper] = append(result["@deref:"+wrapper], alias)
				}
			}
		}
	}
	return result, rows.Err()
}

func indexSemanticVariables(variables []semanticVariable) *variableIndex {
	index := &variableIndex{
		locals: make(map[string][]semanticVariable), fields: make(map[string][]semanticVariable),
		globals: make(map[string][]semanticVariable), callbacks: make(map[string][]semanticVariable),
	}
	for _, variable := range variables {
		switch variable.kind {
		case "field":
			key := shortTypeName(variable.owner) + "\x00" + variable.name
			index.fields[key] = append(index.fields[key], variable)
		case "global":
			index.globals[variable.name] = append(index.globals[variable.name], variable)
		default:
			key := variable.owner + "\x00" + variable.name
			index.locals[key] = append(index.locals[key], variable)
		}
		if variable.kind == "callback" {
			key := variable.owner + "\x00" + variable.name
			index.callbacks[key] = append(index.callbacks[key], variable)
		}
	}
	for _, groups := range []map[string][]semanticVariable{index.locals, index.fields, index.globals, index.callbacks} {
		for key := range groups {
			sort.Slice(groups[key], func(i, j int) bool {
				left, right := groups[key][i], groups[key][j]
				if left.line != right.line {
					return left.line < right.line
				}
				if left.path != right.path {
					return left.path < right.path
				}
				if left.kind != right.kind {
					return left.kind < right.kind
				}
				if left.typeName != right.typeName {
					return left.typeName < right.typeName
				}
				if left.target != right.target {
					return left.target < right.target
				}
				return left.owner < right.owner
			})
		}
	}
	return index
}

type macroTarget struct {
	id, fileID int64
	qualified  string
	path       string
	arity      int
}

func loadMacroNames(tx *sql.Tx) (map[string][]macroTarget, error) {
	rows, err := tx.Query(`SELECT m.id, m.file_id, m.name, m.qualified_name, m.arity, f.path
		FROM macros m JOIN files f ON f.id=m.file_id ORDER BY m.name,f.path,m.line,m.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][]macroTarget)
	for rows.Next() {
		var name string
		var macro macroTarget
		if err := rows.Scan(&macro.id, &macro.fileID, &name, &macro.qualified, &macro.arity, &macro.path); err != nil {
			return nil, err
		}
		result[name] = append(result[name], macro)
	}
	return result, rows.Err()
}

func matchingMacro(macros []macroTarget, call semanticCall, includes []string) (macroTarget, bool) {
	bestScore := -1.0
	var best macroTarget
	for _, macro := range macros {
		if macro.arity >= 0 && call.arity >= 0 && macro.arity != call.arity {
			continue
		}
		score := directoryProximity(call.path, macro.path)
		if directlyIncludes(includes, macro.path) {
			score += 2
		}
		if macro.fileID == call.fileID {
			score += 3
		}
		if score > bestScore || score == bestScore && macro.path < best.path {
			bestScore = score
			best = macro
		}
	}
	return best, bestScore >= 0
}

func loadIncludeFacts(tx *sql.Tx) (map[int64][]string, error) {
	rows, err := tx.Query(`SELECT i.file_id, i.included FROM includes i
		UNION ALL
		SELECT e.file_id, f.path FROM include_edges e JOIN files f ON f.id=e.included_file_id
		UNION ALL
		SELECT e.file_id, dependency.included FROM include_edges e
		JOIN includes dependency ON dependency.file_id=e.included_file_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[int64][]string)
	for rows.Next() {
		var fileID int64
		var included string
		if err := rows.Scan(&fileID, &included); err != nil {
			return nil, err
		}
		result[fileID] = append(result[fileID], strings.Trim(included, `\"<>`))
	}
	return result, rows.Err()
}

func loadParentTypes(tx *sql.Tx) (map[string][]string, error) {
	rows, err := tx.Query("SELECT class_name, parent_name FROM inheritance ORDER BY class_name,parent_name,relation_kind")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][]string)
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			return nil, err
		}
		result[shortTypeName(child)] = append(result[shortTypeName(child)], shortTypeName(parent))
	}
	return result, rows.Err()
}

func inferGoInterfaceImplementations(symbols []semanticSymbol, parents map[string][]string) {
	type kindLanguage struct{ kind, language string }
	types := make(map[string]kindLanguage)
	methods := make(map[string]map[string]bool)
	for _, symbol := range symbols {
		if symbol.kind != "method" {
			types[shortTypeName(symbol.qualified)] = kindLanguage{symbol.kind, symbol.language}
			continue
		}
		owner := shortTypeName(qualifiedOwner(symbol.qualified))
		if methods[owner] == nil {
			methods[owner] = make(map[string]bool)
		}
		methods[owner][symbol.name+"#"+itoa(symbol.arity)+"#"+symbol.parameterTypes] = true
	}
	var interfaces, concrete []string
	for name, typ := range types {
		if typ.language != "go" {
			continue
		}
		if typ.kind == "interface" {
			interfaces = append(interfaces, name)
		} else if typ.kind == "struct" || typ.kind == "type" {
			concrete = append(concrete, name)
		}
	}
	sort.Strings(interfaces)
	sort.Strings(concrete)
	for _, implementation := range concrete {
		for _, contract := range interfaces {
			required := methods[contract]
			if len(required) == 0 {
				continue
			}
			complete := true
			for signature := range required {
				if !methods[implementation][signature] {
					complete = false
					break
				}
			}
			if complete && !containsString(parents[implementation], contract) {
				parents[implementation] = append(parents[implementation], contract)
			}
		}
	}
}

func expandBlanketImplementations(parents map[string][]string) {
	var rules [][2]string
	for child, targets := range parents {
		if !strings.HasPrefix(child, "@blanket:") {
			continue
		}
		bound := strings.TrimPrefix(child, "@blanket:")
		for _, target := range targets {
			rules = append(rules, [2]string{bound, target})
		}
	}
	for implementation := range parents {
		if strings.HasPrefix(implementation, "@blanket:") {
			continue
		}
		ancestors := append([]string{implementation}, transitiveParents(implementation, parents)...)
		for _, rule := range rules {
			if containsType(ancestors, rule[0]) && !containsString(parents[implementation], rule[1]) {
				parents[implementation] = append(parents[implementation], rule[1])
			}
		}
	}
}

func inferRustDerefParents(aliases map[string][]semanticAlias, parents map[string][]string) {
	for key, facts := range aliases {
		if !strings.HasPrefix(key, "@deref:") {
			continue
		}
		owner := strings.TrimPrefix(key, "@deref:")
		for _, fact := range facts {
			target := shortTypeName(fact.target)
			if target != "" && !containsString(parents[owner], target) {
				parents[owner] = append(parents[owner], target)
			}
		}
	}
	for _, fact := range aliases["Target"] {
		ownerPath := strings.TrimSuffix(fact.owner, "::"+fact.name)
		owner := shortTypeName(ownerPath)
		if owner == "" {
			continue
		}
		derefOwner := false
		for _, parent := range append([]string{owner}, transitiveParents(owner, parents)...) {
			if shortTypeName(parent) == "Deref" {
				derefOwner = true
				break
			}
		}
		if derefOwner {
			target := shortTypeName(fact.target)
			if target != "" && !containsString(parents[owner], target) {
				parents[owner] = append(parents[owner], target)
			}
		}
	}
}

func containsType(values []string, expected string) bool {
	for _, value := range values {
		if sameType(value, expected) {
			return true
		}
	}
	return false
}

func cloneParentMap(source map[string][]string) map[string][]string {
	result := make(map[string][]string, len(source))
	for child, parents := range source {
		result[child] = append([]string(nil), parents...)
	}
	return result
}

func persistInferredTypeRelations(tx *sql.Tx, symbols []semanticSymbol, source, expanded map[string][]string) error {
	typeLocation := make(map[string]semanticSymbol)
	for _, symbol := range symbols {
		if symbol.kind == "method" || symbol.kind == "function" || symbol.kind == "property" {
			continue
		}
		name := shortTypeName(symbol.qualified)
		if _, exists := typeLocation[name]; !exists {
			typeLocation[name] = symbol
		}
	}
	insert, err := tx.Prepare(`INSERT INTO inheritance(class_name,parent_name,file_id,line,relation_kind)
		VALUES (?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer insert.Close()
	var children []string
	for child := range expanded {
		children = append(children, child)
	}
	sort.Strings(children)
	for _, child := range children {
		location, ok := typeLocation[shortTypeName(child)]
		if !ok || strings.HasPrefix(child, "@blanket:") {
			continue
		}
		parents := append([]string(nil), expanded[child]...)
		sort.Strings(parents)
		for _, parent := range parents {
			if containsType(source[child], parent) {
				continue
			}
			kind := "inferred_implements"
			if location.language == "rust" {
				kind = "inferred_semantic"
			}
			if _, err := insert.Exec(child, parent, location.fileID, 0, kind); err != nil {
				return err
			}
		}
	}
	return nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func dynamicDispatchTargets(call semanticCall, receiverType string, primary semanticSymbol, candidates []semanticSymbol, allSymbols map[string][]semanticSymbol, parents map[string][]string) []rankedTarget {
	if receiverType == "" || primary.kind != "method" {
		return nil
	}
	baseOwner := shortTypeName(qualifiedOwner(primary.qualified))
	baseKind := typeKindForName(baseOwner, allSymbols)
	dynamicBase := csvContains(primary.modifiers, "virtual") || csvContains(primary.modifiers, "abstract") || csvContains(primary.modifiers, "override")
	switch primary.language {
	case "go":
		dynamicBase = baseKind == "interface"
	case "rust":
		dynamicBase = baseKind == "trait"
	case "java":
		dynamicBase = baseKind == "interface" || !csvContains(primary.modifiers, "static") && !csvContains(primary.modifiers, "final") && !csvContains(primary.modifiers, "private")
	case "csharp":
		dynamicBase = dynamicBase || baseKind == "interface"
	}
	var overrides []semanticSymbol
	for _, candidate := range candidates {
		if candidate.kind != "method" || candidate.semanticID == primary.semanticID {
			continue
		}
		if call.arity >= 0 && candidate.arity >= 0 && candidate.arity != call.arity {
			continue
		}
		candidateOwner := shortTypeName(qualifiedOwner(candidate.qualified))
		if !isDescendantType(candidateOwner, baseOwner, parents) && !isDescendantType(candidateOwner, receiverType, parents) {
			continue
		}
		if csvContains(candidate.modifiers, "override") {
			dynamicBase = true
		}
		overrides = append(overrides, candidate)
	}
	if !dynamicBase || len(overrides) == 0 {
		return nil
	}
	result := make([]rankedTarget, 0, min(len(overrides), maxCandidatesPerCall))
	sort.Slice(overrides, func(i, j int) bool { return overrides[i].qualified < overrides[j].qualified })
	for _, override := range overrides {
		result = append(result, rankedTarget{symbol: override, confidence: 0.78, basis: "dynamic-override"})
		if len(result) >= maxCandidatesPerCall {
			break
		}
	}
	return result
}

func typeKindForName(name string, symbols map[string][]semanticSymbol) string {
	for _, symbol := range symbols[shortTypeName(name)] {
		if symbol.kind != "method" && symbol.kind != "function" && symbol.kind != "property" {
			return symbol.kind
		}
	}
	return ""
}

func isDescendantType(candidate, parent string, parents map[string][]string) bool {
	if sameType(candidate, parent) {
		return true
	}
	for _, ancestor := range transitiveParents(candidate, parents) {
		if sameType(ancestor, parent) {
			return true
		}
	}
	return false
}

func csvContains(value, expected string) bool {
	for _, item := range strings.Split(value, ",") {
		if strings.TrimSpace(item) == expected {
			return true
		}
	}
	return false
}

func resolveReceiverType(call semanticCall, variables *variableIndex, aliases map[string][]semanticAlias, symbols map[string][]semanticSymbol, parents map[string][]string) string {
	receiver := strings.TrimSpace(call.receiver)
	if receiver == "" {
		return ""
	}
	segments := splitReceiverChain(receiver)
	if len(segments) == 0 {
		return ""
	}
	owner := shortTypeName(qualifiedOwner(call.caller))
	current := ""
	rootName, rootArity, rootCall := receiverSegment(segments[0])
	if rootName == "this" || rootName == "self" || rootName == "Self" {
		current = owner
	} else if rootCall {
		current = uniqueReturnType(symbols[rootName], "", rootArity, symbols, aliases, parents)
		if current == "" && looksLikeType(rootName) {
			current = rootName
		}
	} else if variable := bestVariable(variables, call, owner, rootName); variable != nil {
		current = resolvedVariableType(*variable, call, variables, map[string]bool{})
	} else if looksLikeType(rootName) {
		current = rootName
	}
	current = resolveProjectType(current, call, variables, aliases)
	for _, rawSegment := range segments[1:] {
		if current == "" {
			break
		}
		name, arity, isCall := receiverSegment(rawSegment)
		current = unwrapReceiverContainer(current)
		if isCall {
			current = uniqueReturnType(symbols[name], current, arity, symbols, aliases, parents)
			current = resolveProjectType(current, call, variables, aliases)
		} else if variable := fieldVariable(variables, current, name, parents); variable != nil {
			current = resolveProjectType(variable.typeName, call, variables, aliases)
		} else {
			return ""
		}
	}
	return cleanTypeName(unwrapReceiverContainer(current))
}

func resolveProjectArgumentTypes(call semanticCall, variables *variableIndex, aliases map[string][]semanticAlias, symbols map[string][]semanticSymbol, parents map[string][]string) string {
	if call.argumentExpressions == "" {
		return call.argumentTypes
	}
	expressions := strings.Split(call.argumentExpressions, "\x1f")
	types := strings.Split(call.argumentTypes, ",")
	if len(types) != len(expressions) {
		types = make([]string, len(expressions))
	}
	owner := shortTypeName(qualifiedOwner(call.caller))
	for index, expression := range expressions {
		if types[index] != "" && types[index] != "unknown" {
			continue
		}
		expression = strings.TrimSpace(expression)
		if literal := inferArgumentTypes([]string{expression}); literal != "unknown" {
			types[index] = literal
			continue
		}
		identifier := strings.Trim(expression, "*&()[] ")
		if !strings.ContainsAny(identifier, ".->: (") {
			if variable := bestVariable(variables, call, owner, identifier); variable != nil {
				types[index] = resolveProjectType(resolvedVariableType(*variable, call, variables, map[string]bool{}), call, variables, aliases)
				continue
			}
		}
		if strings.HasPrefix(expression, "new ") {
			types[index] = inferredConstructorType(expression)
			continue
		}
		if open := strings.Index(expression, "("); open > 0 {
			calleeRaw := strings.TrimSpace(expression[:open])
			calleeName := shortCallee(calleeRaw)
			arity := 0
			if close := matchingDelimiter(expression, open, '(', ')'); close > open {
				arguments := strings.TrimSpace(expression[open+1 : close])
				if arguments != "" {
					arity = len(splitTopLevel(arguments))
				}
			}
			receiverExpression := callReceiver(calleeRaw, calleeName)
			receiverType := ""
			if receiverExpression != "" {
				nested := call
				nested.name, nested.receiver, nested.raw, nested.arity = calleeName, receiverExpression, calleeRaw, arity
				receiverType = resolveReceiverType(nested, variables, aliases, symbols, parents)
			}
			types[index] = uniqueReturnType(symbols[calleeName], receiverType, arity, symbols, aliases, parents)
			if types[index] == "" && looksLikeType(calleeName) {
				types[index] = calleeName
			}
		}
		if types[index] == "" {
			types[index] = "unknown"
		}
	}
	return strings.Join(types, ",")
}

func splitReceiverChain(value string) []string {
	var result []string
	start, depth := 0, 0
	quote := byte(0)
	appendPart := func(end int) {
		if part := strings.TrimSpace(value[start:end]); part != "" {
			result = append(result, part)
		}
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if quote != 0 {
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '\'' || char == '"' {
			quote = char
			continue
		}
		if depth == 0 && char == '-' && index+1 < len(value) && value[index+1] == '>' {
			appendPart(index)
			index++
			start = index + 1
			continue
		}
		if depth == 0 && char == ':' && index+1 < len(value) && value[index+1] == ':' {
			appendPart(index)
			index++
			start = index + 1
			continue
		}
		if depth == 0 && char == '.' {
			appendPart(index)
			start = index + 1
			continue
		}
		switch char {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}', '>':
			if depth > 0 {
				depth--
			}
		}
	}
	if tail := strings.TrimSpace(value[start:]); tail != "" {
		result = append(result, tail)
	}
	return result
}

func receiverSegment(value string) (string, int, bool) {
	value = strings.Trim(strings.TrimSpace(value), "*& ")
	open := strings.Index(value, "(")
	if open < 0 {
		return strings.Trim(value, "[] "), -1, false
	}
	close := matchingDelimiter(value, open, '(', ')')
	if close < 0 {
		return strings.TrimSpace(value[:open]), -1, true
	}
	args := strings.TrimSpace(value[open+1 : close])
	if args == "" {
		return strings.TrimSpace(value[:open]), 0, true
	}
	return strings.TrimSpace(value[:open]), len(splitTopLevel(args)), true
}

func uniqueReturnType(candidates []semanticSymbol, receiver string, arity int, allSymbols map[string][]semanticSymbol, aliases map[string][]semanticAlias, parents map[string][]string) string {
	returns := make(map[string]bool)
	for _, candidate := range candidates {
		if candidate.returnType == "" {
			continue
		}
		if arity >= 0 && candidateCallArity(candidate) >= 0 && arity != candidateCallArity(candidate) {
			continue
		}
		if receiver != "" && candidate.kind == "method" && !receiverMatchesSymbol(receiver, candidate, parents) {
			continue
		}
		returnType := substituteGenericReturn(candidate.returnType, receiver, candidate, allSymbols)
		returnType = substituteAssociatedReturn(returnType, receiver, aliases)
		returns[returnType] = true
	}
	if len(returns) != 1 {
		return ""
	}
	for result := range returns {
		return result
	}
	return ""
}

func substituteAssociatedReturn(returnType, receiver string, aliases map[string][]semanticAlias) string {
	if receiver == "" {
		return returnType
	}
	marker := strings.LastIndex(returnType, "::")
	if marker < 0 {
		return returnType
	}
	associated := strings.TrimSpace(returnType[marker+2:])
	receiverName := shortTypeName(receiver)
	for _, alias := range aliases[associated] {
		if strings.Contains(alias.owner, receiverName) || strings.Contains(alias.qualified, receiverName) {
			return alias.target
		}
	}
	return returnType
}

func substituteGenericReturn(returnType, receiver string, method semanticSymbol, symbols map[string][]semanticSymbol) string {
	if receiver == "" || !isSimpleTypeParameter(returnType) {
		return returnType
	}
	arguments := genericArguments(receiver)
	if arguments == "" {
		return returnType
	}
	owner := shortTypeName(qualifiedOwner(method.qualified))
	var parameters []string
	for _, symbol := range symbols[owner] {
		if symbol.kind == "method" || symbol.kind == "function" {
			continue
		}
		parameters = typeParameterNames(symbol.signature, owner)
		if len(parameters) > 0 {
			break
		}
	}
	values := splitTopLevel(arguments)
	for index, parameter := range parameters {
		if parameter == returnType && index < len(values) {
			return strings.TrimSpace(values[index])
		}
	}
	return returnType
}

func typeParameterNames(signature, typeName string) []string {
	start := strings.Index(signature, typeName)
	if start < 0 {
		return nil
	}
	rest := signature[start+len(typeName):]
	open := strings.IndexAny(rest, "<[")
	if open < 0 {
		return nil
	}
	opening := rune(rest[open])
	closing := '>'
	if opening == '[' {
		closing = ']'
	}
	close := matchingDelimiter(rest, open, opening, closing)
	if close < 0 {
		return nil
	}
	var result []string
	for _, raw := range splitTopLevel(rest[open+1 : close]) {
		raw = strings.TrimSpace(raw)
		for _, separator := range []string{":", " extends ", " super ", " ", ","} {
			if index := strings.Index(raw, separator); index >= 0 {
				raw = raw[:index]
			}
		}
		if raw != "" {
			result = append(result, raw)
		}
	}
	return result
}

func isSimpleTypeParameter(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, ":<>,[]*& ") {
		return false
	}
	return true
}

func resolveProjectType(typeName string, call semanticCall, variables *variableIndex, aliases map[string][]semanticAlias) string {
	typeName = resolveTypeAlias(typeName, call, variables)
	seen := make(map[string]bool)
	for typeName != "" {
		base := shortTypeName(cleanTypeName(typeName))
		if seen[base] {
			break
		}
		seen[base] = true
		choices := aliases[base]
		var chosen *semanticAlias
		for index := range choices {
			alias := &choices[index]
			if alias.fileID == call.fileID {
				chosen = alias
				break
			}
			if chosen == nil {
				chosen = alias
			}
		}
		if chosen == nil {
			break
		}
		typeName = substituteAliasTarget(typeName, *chosen)
	}
	return typeName
}

func substituteAliasTarget(instantiated string, alias semanticAlias) string {
	target := strings.TrimSpace(alias.target)
	arguments := genericArguments(instantiated)
	if strings.TrimSpace(alias.parameters) == "" || strings.TrimSpace(arguments) == "" {
		return target
	}
	parameters := splitTopLevel(alias.parameters)
	values := splitTopLevel(arguments)
	if len(parameters) == len(values) {
		for index := range parameters {
			fields := strings.Fields(strings.TrimSpace(parameters[index]))
			if len(fields) == 0 {
				continue
			}
			name := fields[0]
			target = regexpWordReplace(target, name, strings.TrimSpace(values[index]))
		}
	}
	return target
}

func regexpWordReplace(value, name, replacement string) string {
	if name == "" {
		return value
	}
	var result strings.Builder
	for index := 0; index < len(value); {
		if strings.HasPrefix(value[index:], name) && (index == 0 || !isIdentByte(value[index-1])) && (index+len(name) == len(value) || !isIdentByte(value[index+len(name)])) {
			result.WriteString(replacement)
			index += len(name)
		} else {
			result.WriteByte(value[index])
			index++
		}
	}
	return result.String()
}

func isIdentByte(value byte) bool {
	return value == '_' || value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func unwrapReceiverContainer(value string) string {
	value = strings.TrimSpace(value)
	base := strings.ToLower(shortTypeName(cleanTypeName(value)))
	switch base {
	case "unique_ptr", "shared_ptr", "weak_ptr", "auto_ptr", "box", "rc", "arc", "pin", "option", "optional":
		if arguments := genericArguments(value); arguments != "" {
			return strings.TrimSpace(splitTopLevel(arguments)[0])
		}
	}
	return value
}

func resolveTypeAlias(typeName string, call semanticCall, variables *variableIndex) string {
	seen := make(map[string]bool)
	for typeName != "" && !seen[typeName] {
		seen[typeName] = true
		changed := false
		for _, variable := range variables.locals[call.caller+"\x00"+shortTypeName(typeName)] {
			if variable.kind == "type_parameter" && variable.line <= call.line {
				typeName = variable.typeName
				changed = true
				break
			}
		}
		if !changed {
			break
		}
	}
	return typeName
}

func resolvedVariableType(variable semanticVariable, call semanticCall, variables *variableIndex, seen map[string]bool) string {
	key := variable.owner + "\x00" + variable.name + "\x00" + itoa(variable.line)
	if seen[key] {
		return ""
	}
	seen[key] = true
	typeName := variable.typeName
	if typeName != "" && typeName != "auto" && typeName != "var" {
		return typeName
	}
	if variable.target == "" {
		return ""
	}
	priorCall := call
	priorCall.line = variable.line
	parts := strings.FieldsFunc(variable.target, func(char rune) bool { return char == '.' || char == '-' || char == '>' })
	if len(parts) == 0 {
		return ""
	}
	if source := bestVariable(variables, priorCall, shortTypeName(qualifiedOwner(call.caller)), parts[0]); source != nil {
		typeName = resolvedVariableType(*source, priorCall, variables, seen)
		for _, field := range parts[1:] {
			fieldFact := fieldVariable(variables, typeName, field, nil)
			if fieldFact == nil {
				return ""
			}
			typeName = fieldFact.typeName
		}
		return typeName
	}
	return ""
}

func bestVariable(variables *variableIndex, call semanticCall, owner, name string) *semanticVariable {
	localFacts := variables.locals[call.caller+"\x00"+name]
	for index := len(localFacts) - 1; index >= 0; index-- {
		if localFacts[index].line <= call.line {
			return &localFacts[index]
		}
	}
	fieldFacts := variables.fields[shortTypeName(owner)+"\x00"+name]
	if len(fieldFacts) > 0 {
		return &fieldFacts[len(fieldFacts)-1]
	}
	globalFacts := variables.globals[name]
	var fallback *semanticVariable
	for index := range globalFacts {
		variable := &globalFacts[index]
		if variable.fileID == call.fileID {
			return variable
		}
		fallback = variable
	}
	return fallback
}

func fieldVariable(variables *variableIndex, owner, name string, parents map[string][]string) *semanticVariable {
	owners := append([]string{shortTypeName(owner)}, transitiveParents(owner, parents)...)
	for _, candidateOwner := range owners {
		facts := variables.fields[shortTypeName(candidateOwner)+"\x00"+name]
		if len(facts) > 0 {
			return &facts[len(facts)-1]
		}
	}
	return nil
}

func lookupCallback(call semanticCall, variables *variableIndex) (*semanticVariable, bool) {
	callbackName := call.name
	if call.receiver != "" && (call.name == "run" || call.name == "Run" || call.name == "invoke" || call.name == "Invoke" || call.name == "call" || call.name == "apply") {
		parts := strings.FieldsFunc(call.receiver, func(char rune) bool { return char == '.' || char == ':' || char == '-' || char == '>' })
		if len(parts) > 0 {
			callbackName = strings.TrimSpace(parts[0])
		}
	}
	for _, owner := range []string{call.caller, qualifiedOwner(call.caller), ""} {
		facts := variables.callbacks[owner+"\x00"+callbackName]
		for index := len(facts) - 1; index >= 0; index-- {
			if owner != call.caller || facts[index].line <= call.line {
				return &facts[index], true
			}
		}
	}
	return nil, false
}

func uniqueQualifiedSymbol(symbols []semanticSymbol, qualified string) *semanticSymbol {
	if qualified == "" {
		return nil
	}
	var found *semanticSymbol
	for index := range symbols {
		if symbols[index].qualified != qualified && !strings.HasSuffix(symbols[index].qualified, "::"+qualified) {
			continue
		}
		if found != nil && found.qualified != symbols[index].qualified {
			return nil
		}
		found = &symbols[index]
	}
	return found
}

func rankSemanticCandidates(call semanticCall, receiverType string, candidates []semanticSymbol, includes map[int64][]string, parents map[string][]string) []rankedTarget {
	bestByTarget := make(map[string]rankedTarget)
	for _, symbol := range candidates {
		if receiverType != "" {
			if symbol.kind != "method" && symbol.kind != "property" {
				continue
			}
			if !receiverMatchesSymbol(receiverType, symbol, parents) {
				continue
			}
		} else if call.language == "cpp" && !cppSymbolVisible(call, symbol, includes[call.fileID], parents) {
			continue
		}
		score, reasons := semanticCandidateScore(call, receiverType, symbol, includes[call.fileID], len(candidates), parents)
		key := fmt.Sprintf("%d", symbol.semanticID)
		candidate := rankedTarget{symbol: symbol, confidence: score, basis: strings.Join(reasons, "+")}
		if current, ok := bestByTarget[key]; !ok || candidate.confidence > current.confidence {
			bestByTarget[key] = candidate
		}
	}
	result := make([]rankedTarget, 0, len(bestByTarget))
	for _, candidate := range bestByTarget {
		result = append(result, candidate)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].confidence != result[j].confidence {
			return result[i].confidence > result[j].confidence
		}
		if result[i].symbol.qualified != result[j].symbol.qualified {
			return result[i].symbol.qualified < result[j].symbol.qualified
		}
		if result[i].symbol.parameterTypes != result[j].symbol.parameterTypes {
			return result[i].symbol.parameterTypes < result[j].symbol.parameterTypes
		}
		if result[i].symbol.path != result[j].symbol.path {
			return result[i].symbol.path < result[j].symbol.path
		}
		return result[i].symbol.semanticID < result[j].symbol.semanticID
	})
	return result
}

func semanticCandidateScore(call semanticCall, receiverType string, symbol semanticSymbol, included []string, count int, parents map[string][]string) (float64, []string) {
	// A compact logistic evidence model keeps scores monotonic, bounded, and
	// calibratable. Weights are intentionally explicit so a future labelled
	// corpus can fit replacements without changing resolution control flow.
	logOdds := -1.50
	reasons := []string{"name=-1.50"}
	if call.qualified == symbol.qualified {
		logOdds += 5.0
		reasons = append(reasons, "qualified=5.00")
	} else if receiverType != "" && receiverMatchesSymbol(receiverType, symbol, parents) {
		weight, label := receiverEvidenceWeight(receiverType, symbol, parents)
		logOdds += weight
		reasons = append(reasons, fmt.Sprintf("%s=%.2f", label, weight))
	} else if owner := qualifiedOwner(call.caller); owner != "" && ownerCompatible(owner, qualifiedOwner(symbol.qualified), parents) {
		logOdds += 3.2
		reasons = append(reasons, "caller-owner=3.20")
	} else if count == 1 {
		logOdds += 1.8
		reasons = append(reasons, "unique-name=1.80")
	}
	effectiveArity := candidateCallArity(symbol)
	if call.arity >= 0 && effectiveArity >= 0 {
		if call.arity == effectiveArity {
			logOdds += 1.0
			reasons = append(reasons, "arity=1.00")
		} else {
			logOdds -= 3.0
			reasons = append(reasons, "arity-mismatch=-3.00")
		}
	}
	if typeAdjustment := argumentTypeAdjustment(call.argumentTypes, symbol); typeAdjustment != 0 {
		weight := typeAdjustment * 12
		logOdds += weight
		if typeAdjustment > 0 {
			reasons = append(reasons, fmt.Sprintf("argument-types=%.2f", weight))
		} else {
			reasons = append(reasons, fmt.Sprintf("argument-type-mismatch=%.2f", weight))
		}
	}
	if symbolOccursInFile(symbol, call.fileID) {
		logOdds += 0.7
		reasons = append(reasons, "same-file=0.70")
	}
	if symbolIncluded(included, symbol) {
		logOdds += 1.25
		reasons = append(reasons, "include=1.25")
	}
	if proximity := symbolDirectoryProximity(call.path, symbol); proximity > 0 {
		weight := 0.8 * proximity
		logOdds += weight
		reasons = append(reasons, fmt.Sprintf("path=%.2f", weight))
	}
	return calibratedProbability(logOdds), reasons
}

func cppSymbolVisible(call semanticCall, symbol semanticSymbol, includes []string, parents map[string][]string) bool {
	if symbolOccursInFile(symbol, call.fileID) || symbolIncluded(includes, symbol) || call.qualified == symbol.qualified {
		return true
	}
	for _, sourceRoot := range symbol.occurrenceRoots {
		if sourceRoot != "" && sameFSPath(sourceRoot, call.sourceRoot) {
			return true
		}
	}
	callerOwner := qualifiedOwner(call.caller)
	symbolOwner := qualifiedOwner(symbol.qualified)
	if callerOwner != "" && symbolOwner != "" && ownerCompatible(callerOwner, symbolOwner, parents) {
		return true
	}
	// Unqualified free functions in the same namespace remain visible even
	// when their declaration occurrence was elided by a generated header.
	return symbol.kind == "function" && callerOwner != "" && callerOwner == symbolOwner
}

func sameFSPath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func symbolOccursInFile(symbol semanticSymbol, fileID int64) bool {
	for _, occurrenceFileID := range symbol.occurrenceFileIDs {
		if occurrenceFileID == fileID {
			return true
		}
	}
	return symbol.fileID == fileID
}

func symbolIncluded(includes []string, symbol semanticSymbol) bool {
	for _, path := range symbol.occurrencePaths {
		if directlyIncludes(includes, path) {
			return true
		}
	}
	return directlyIncludes(includes, symbol.path)
}

func symbolDirectoryProximity(callPath string, symbol semanticSymbol) float64 {
	best := directoryProximity(callPath, symbol.path)
	for _, path := range symbol.occurrencePaths {
		if proximity := directoryProximity(callPath, path); proximity > best {
			best = proximity
		}
	}
	return best
}

func calibratedProbability(logOdds float64) float64 {
	if logOdds > 20 {
		return 1
	}
	if logOdds < -20 {
		return 0
	}
	return 1 / (1 + math.Exp(-logOdds))
}

func confidenceLogOdds(probability float64) float64 {
	if probability <= 0 {
		return -20
	}
	if probability >= 1 {
		return 20
	}
	return math.Log(probability / (1 - probability))
}

func argumentTypeAdjustment(argumentTypes string, symbol semanticSymbol) float64 {
	if argumentTypes == "" || symbol.signature == "" {
		return 0
	}
	arguments := strings.Split(argumentTypes, ",")
	parameters := signatureParameters(symbol.language, symbol.signature)
	if csvContains(symbol.modifiers, "extension") && len(parameters) > 0 {
		parameters = parameters[1:]
	}
	if len(arguments) != len(parameters) || len(arguments) == 0 {
		return 0
	}
	known := 0
	matches := 0
	for index, argument := range arguments {
		if argument == "unknown" || argument == "null" {
			continue
		}
		known++
		if compatibleTypeKind(argument, parameters[index].typeName) {
			matches++
		}
	}
	if known == 0 {
		return 0
	}
	ratio := float64(matches) / float64(known)
	return 0.08*ratio - 0.06*(1-ratio)
}

func receiverMatchesSymbol(receiverType string, symbol semanticSymbol, parents map[string][]string) bool {
	if ownerCompatible(receiverType, qualifiedOwner(symbol.qualified), parents) {
		return true
	}
	if csvContains(symbol.modifiers, "extension") {
		parameters := signatureParameters(symbol.language, symbol.signature)
		if len(parameters) > 0 {
			return ownerCompatible(receiverType, normalizeTypeExpression(parameters[0].typeName), parents)
		}
	}
	return false
}

func receiverEvidenceWeight(receiverType string, symbol semanticSymbol, parents map[string][]string) (float64, string) {
	if sameType(receiverType, qualifiedOwner(symbol.qualified)) {
		return 4.2, "receiver-direct"
	}
	if csvContains(symbol.modifiers, "extension") {
		return 3.6, "receiver-extension"
	}
	if ownerCompatible(receiverType, qualifiedOwner(symbol.qualified), parents) {
		return 3.4, "receiver-inherited"
	}
	return 0, "receiver-none"
}

func candidateCallArity(symbol semanticSymbol) int {
	if csvContains(symbol.modifiers, "extension") && symbol.arity > 0 {
		return symbol.arity - 1
	}
	return symbol.arity
}

func compatibleTypeKind(argument, parameter string) bool {
	parameter = strings.ToLower(cleanTypeName(parameter))
	argumentType := strings.ToLower(cleanTypeName(argument))
	if argumentType != "" && argumentType != "unknown" && argumentType != "null" && argumentType == parameter {
		return true
	}
	switch argument {
	case "bool":
		return parameter == "bool" || parameter == "boolean"
	case "string":
		return strings.Contains(parameter, "string") || strings.Contains(parameter, "char")
	case "char":
		return strings.Contains(parameter, "char") || parameter == "rune" || parameter == "byte"
	case "float":
		return strings.Contains(parameter, "float") || strings.Contains(parameter, "double") || parameter == "decimal"
	case "int":
		for _, marker := range []string{"int", "long", "short", "size_t", "uint", "usize", "isize", "byte"} {
			if strings.Contains(parameter, marker) {
				return true
			}
		}
	}
	return false
}

func ownerCompatible(receiverType, symbolOwner string, parents map[string][]string) bool {
	receiverType = shortTypeName(receiverType)
	if sameType(receiverType, symbolOwner) {
		return true
	}
	for _, parent := range transitiveParents(receiverType, parents) {
		if sameType(parent, symbolOwner) {
			return true
		}
	}
	return false
}

func transitiveParents(typeName string, parents map[string][]string) []string {
	queue := append([]string(nil), parents[shortTypeName(typeName)]...)
	seen := make(map[string]bool)
	var result []string
	for len(queue) > 0 {
		current := shortTypeName(queue[0])
		queue = queue[1:]
		if current == "" || seen[current] {
			continue
		}
		seen[current] = true
		result = append(result, current)
		queue = append(queue, parents[current]...)
	}
	return result
}

func directlyIncludes(includes []string, symbolPath string) bool {
	cleanPath := filepath.ToSlash(symbolPath)
	base := filepath.Base(symbolPath)
	for _, included := range includes {
		included = filepath.ToSlash(strings.TrimSpace(included))
		if included == base || strings.HasSuffix(cleanPath, "/"+included) {
			return true
		}
	}
	return false
}

func directoryProximity(left, right string) float64 {
	leftParts := strings.Split(strings.ToLower(filepath.ToSlash(filepath.Dir(left))), "/")
	rightParts := strings.Split(strings.ToLower(filepath.ToSlash(filepath.Dir(right))), "/")
	common := 0
	for common < len(leftParts) && common < len(rightParts) && leftParts[common] == rightParts[common] {
		common++
	}
	remaining := len(leftParts) + len(rightParts) - 2*common
	return 1 / float64(1+remaining)
}

func shortTypeName(value string) string {
	value = cleanTypeName(value)
	if index := strings.LastIndex(value, "::"); index >= 0 {
		value = value[index+2:]
	}
	return value
}

func sameType(left, right string) bool {
	return shortTypeName(left) != "" && shortTypeName(left) == shortTypeName(right)
}

func looksLikeType(value string) bool {
	return value != "" && value[0] >= 'A' && value[0] <= 'Z'
}

var externalCallNames = map[string]bool{
	"abort": true, "abs": true, "atoi": true, "calloc": true, "exit": true, "fclose": true,
	"fopen": true, "fprintf": true, "free": true, "fread": true, "fseek": true, "fwrite": true,
	"malloc": true, "max": true, "memcpy": true, "memmove": true, "memset": true, "min": true,
	"printf": true, "qsort": true, "realloc": true, "scanf": true, "snprintf": true, "sprintf": true,
	"sscanf": true, "strcat": true, "strcmp": true, "strcpy": true, "strlen": true, "strncmp": true,
	"strncpy": true, "strstr": true, "vsnprintf": true, "wsprintf": true,
	"CreateFile": true, "CloseHandle": true, "DeleteFile": true, "GetLastError": true,
	"GetPrivateProfileInt": true, "GetPrivateProfileString": true, "LoadLibrary": true,
	"GetProcAddress": true, "MessageBox": true, "OutputDebugString": true, "ReadFile": true,
	"SetFilePointer": true, "Sleep": true, "WriteFile": true, "GetTickCount": true, "timeGetTime": true,
	"DeleteObject": true, "FreeLibrary": true, "IsEqualGUID": true, "MAKELONG": true,
	"MessageBoxA": true, "MessageBoxW": true, "PlaySound": true, "PlaySoundA": true,
	"PlaySoundW": true, "SelectObject": true, "SendMessage": true, "FindWindow": true,
	"FindWindowA": true, "FindWindowW": true, "GetSystemMetrics": true,
	"DeleteCriticalSection": true, "DestroyWindow": true, "EnterCriticalSection": true,
	"LeaveCriticalSection": true, "WSAGetLastError": true, "DispatchMessage": true,
	"DispatchMessageA": true, "DispatchMessageW": true, "GetClientRect": true,
	"GetTickCount64": true, "LoadImage": true, "LoadImageA": true, "LoadImageW": true,
	"SetThreadPriority": true, "WaitForSingleObject": true, "_chdir": true,
	"mciSendCommand": true, "mciSendCommandA": true, "mciSendCommandW": true,
	"mmioDescend": true, "mmioFOURCC": true,
	"MultiByteToWideChar": true,
	"FAILED":              true, "RGB": true, "ZeroMemory": true,
	"const_cast": true, "dynamic_cast": true, "reinterpret_cast": true, "static_cast": true,
	"cos": true, "cosf": true, "fabs": true, "pow": true, "rand": true, "sin": true,
	"sinf": true, "sqrt": true, "srand": true, "strchr": true, "strerror": true,
	"access": true, "strtok": true, "tan": true, "vsprintf": true, "write": true,
	"gzread": true, "gzwrite": true, "putShortMSB": true, "send_bits": true, "flush_pending": true,
	"ReferenceEquals": true, "range": true,
	"CPoint": true, "CRect": true, "CSize": true, "Rect": true,
}

var wellKnownExternalMacros = map[string]bool{
	"ASSERT": true, "Assert": true, "DeleteNew": true, "DeleteNewArray": true,
	"DEFINE_GUID": true, "FAILED": true, "RGB": true, "SAFE_DELETE": true,
	"SAFE_DELETE_ARRAY": true, "SUCCEEDED": true, "ZeroMemory": true, "assert": true,
	"HIWORD": true, "LOWORD": true, "va_end": true, "va_start": true,
	"_T": true, "get_byte": true,
}

func isExternalCall(call semanticCall, includes []string, receiverType string, knownTypes map[string]bool, knownTypePaths, knownTypeRoots map[string][]string) bool {
	if externalCallNames[call.name] {
		return true
	}
	if standardExternalMemberNames[call.name] {
		return true
	}
	if externalReceiverTypes[shortTypeName(call.name)] {
		return true
	}
	for _, prefix := range []string{"D3D", "Direct", "Imm", "lua_", "gl", "SDL_"} {
		if strings.HasPrefix(call.name, prefix) {
			return true
		}
	}
	qualified := strings.TrimSpace(call.qualified)
	for _, prefix := range []string{"std::", "boost::", "System::", "java::", "javax::", "kotlin::", "core::", "alloc::"} {
		if strings.HasPrefix(qualified, prefix) || strings.HasPrefix(receiverType, prefix) {
			return true
		}
	}
	if externalReceiverTypes[shortTypeName(receiverType)] {
		return true
	}
	if receiverType != "" {
		receiverName := shortTypeName(receiverType)
		if !knownTypes[receiverName] {
			return true
		}
		visible := false
		for _, sourceRoot := range knownTypeRoots[receiverName] {
			if sourceRoot != "" && sameFSPath(sourceRoot, call.sourceRoot) {
				visible = true
				break
			}
		}
		for _, path := range knownTypePaths[receiverName] {
			if filepath.Clean(path) == filepath.Clean(call.path) || directlyIncludes(includes, path) {
				visible = true
				break
			}
		}
		if !visible {
			return true
		}
	}
	if call.language == "go" || call.language == "rust" || call.language == "csharp" || call.language == "java" || call.language == "python" {
		root, _ := splitCalleeRoot(qualified)
		for _, included := range includes {
			normalized := strings.ReplaceAll(strings.TrimSpace(included), ".", "::")
			if root == normalized || strings.HasPrefix(qualified, normalized+"::") || strings.HasSuffix(normalized, "/"+root) {
				return true
			}
		}
	}
	return false
}

func isLanguageConstructCall(call semanticCall) bool {
	name := strings.TrimSpace(call.name)
	if strings.HasPrefix(name, "(") && strings.HasSuffix(name, ")") {
		return true
	}
	if call.language != "cpp" {
		return false
	}
	switch name {
	case "BOOL", "BYTE", "CHAR", "DWORD", "FLOAT", "HRESULT", "INT", "LONG", "LPARAM", "LRESULT", "SHORT", "UINT", "ULONG", "WORD", "WPARAM",
		"bool", "char", "double", "float", "int", "long", "short", "signed", "size_t", "unsigned", "void", "wchar_t":
		return true
	}
	return false
}

var standardExternalMemberNames = map[string]bool{
	"Append": true, "AppendLine": true, "Clear": true, "Close": true, "CompareTo": true,
	"Contains": true, "Dispose": true, "Equals": true, "IsNullOrEmpty": true,
	"IsNullOrWhiteSpace": true, "Length": true, "Open": true, "Read": true,
	"Replace": true, "Split": true, "StartsWith": true, "Substring": true,
	"ToLowerInvariant": true, "ToString": true, "Trim": true, "TryParse": true,
	"ToList": true, "Where": true, "Write": true, "WriteLine": true,
	"at": true, "back": true, "begin": true, "c_str": true, "capacity": true,
	"clear": true, "close": true, "data": true, "emplace": true, "emplace_back": true,
	"empty": true, "end": true, "erase": true, "find": true, "front": true,
	"gcount": true, "insert": true, "isOpen": true, "is_open": true, "pop": true,
	"pop_back": true, "push": true, "push_back": true, "seekg": true,
	"remove":  true,
	"release": true, "reserve": true, "reset": true, "resize": true, "size": true,
	"swap": true, "value_type": true,
}

var externalReceiverTypes = map[string]bool{
	"array": true, "basic_string": true, "deque": true, "list": true, "map": true, "multimap": true,
	"multiset": true, "optional": true, "queue": true, "set": true, "shared_ptr": true, "span": true,
	"stack": true, "string": true, "string_view": true, "unique_ptr": true, "unordered_map": true,
	"unordered_set": true, "variant": true, "vector": true, "weak_ptr": true,
	"ArrayList": true, "Collection": true, "Dictionary": true, "HashMap": true, "HashSet": true,
	"Iterable": true, "List": true, "Map": true, "Optional": true, "Set": true, "Stream": true,
	"Option": true, "Result": true, "String": true, "Vec": true,
	"SolidColorBrush": true, "StringBuilder": true, "bitset": true,
}

func looksLikeMacroName(name string) bool {
	if len(name) < 3 {
		return false
	}
	hasLetter := false
	for _, char := range name {
		if char >= 'A' && char <= 'Z' {
			hasLetter = true
			continue
		}
		if char >= '0' && char <= '9' || char == '_' {
			continue
		}
		return false
	}
	return hasLetter
}
