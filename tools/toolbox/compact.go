package toolbox

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type operationShape struct {
	fields             []string
	required           []string
	requiresConnection bool
}

var connectionFields = []string{
	"connection_profile", "connection_id", "host", "port", "user", "password",
	"key_file", "passphrase", "use_agent", "host_key_check", "jump_host",
	"jump_port", "jump_user", "jump_password", "jump_key_file", "jump_passphrase",
}

var compactOperationShapes = map[string]map[string]operationShape{
	"ssh": {
		"execute": {
			fields:             append(append([]string{}, connectionFields...), "operation", "command", "timeout_sec", "max_output_chars", "output_mode", "quiet", "echo_command", "result_only"),
			required:           []string{"command"},
			requiresConnection: true,
		},
	},
	"ssh_key": {
		"convert": {
			fields:   []string{"operation", "input_path", "output_path", "output_format", "input_passphrase", "output_passphrase", "comment", "overwrite"},
			required: []string{"input_path", "output_path", "output_format"},
		},
	},
	"sftp": {
		"upload": {
			fields:             append(append([]string{}, connectionFields...), "operation", "local_path", "remote_path", "overwrite", "quiet", "result_only"),
			required:           []string{"operation", "local_path", "remote_path"},
			requiresConnection: true,
		},
		"upload_many": {
			fields:             append(append([]string{}, connectionFields...), "operation", "uploads", "overwrite", "quiet", "result_only"),
			required:           []string{"operation", "uploads"},
			requiresConnection: true,
		},
	},
}

func compactInputSchema(encoded []byte, tool, operation string) ([]byte, error) {
	var schema map[string]any
	if err := json.Unmarshal(encoded, &schema); err != nil {
		return nil, err
	}
	properties, _ := schema["properties"].(map[string]any)
	if properties == nil {
		return nil, fmt.Errorf("schema has no object properties")
	}

	operation = strings.ToLower(strings.TrimSpace(operation))
	shape, hasShape := compactOperationShapes[tool][operation]
	if operation != "" && !hasShape {
		available := make([]string, 0, len(compactOperationShapes[tool]))
		for name := range compactOperationShapes[tool] {
			available = append(available, name)
		}
		sort.Strings(available)
		if len(available) == 0 {
			return nil, fmt.Errorf("tool %q has no operation-specific compact schema", tool)
		}
		return nil, fmt.Errorf("compact schema for %s operation %q is unavailable (available: %s)", tool, operation, strings.Join(available, ", "))
	}

	result := map[string]any{"type": "object"}
	filtered := make(map[string]any)
	if hasShape {
		for _, name := range shape.fields {
			if property, ok := properties[name]; ok {
				filtered[name] = property
			}
		}
		if operationProperty, ok := filtered["operation"].(map[string]any); ok {
			copyProperty := make(map[string]any, len(operationProperty)+1)
			for key, value := range operationProperty {
				copyProperty[key] = value
			}
			copyProperty["const"] = operation
			filtered["operation"] = copyProperty
		}
		if len(shape.required) > 0 {
			result["required"] = shape.required
		}
		if shape.requiresConnection {
			result["anyOf"] = []any{
				map[string]any{"required": []string{"connection_id"}},
				map[string]any{"required": []string{"connection_profile"}},
				map[string]any{"required": []string{"host", "user"}},
			}
		}
	} else {
		// Generic compact mode keeps all fields but strips verbose root metadata.
		for name, property := range properties {
			filtered[name] = property
		}
		if required, ok := schema["required"]; ok {
			result["required"] = required
		}
	}
	result["properties"] = filtered
	return json.Marshal(result)
}
