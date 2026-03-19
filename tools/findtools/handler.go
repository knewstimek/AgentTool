package findtools

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type FindToolsInput struct {
	Category string `json:"category,omitempty" jsonschema:"Filter by category: go, dotnet, node, python, java, rust, c_cpp, build, vcs, container, js_runtime, or all (default all)"`
}

type FindToolsOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input FindToolsInput) (*mcp.CallToolResult, FindToolsOutput, error) {
	cat := strings.ToLower(strings.TrimSpace(input.Category))
	if cat == "" {
		cat = "all"
	}

	// Validate category
	if cat != "all" {
		valid := false
		for _, c := range AllCategories() {
			if c == cat {
				valid = true
				break
			}
		}
		if !valid {
			return errorResult(fmt.Sprintf("unknown category: %s (valid: %s, all)", cat, strings.Join(AllCategories(), ", ")))
		}
	}

	results := DiscoverAll(cat)
	output := formatResults(results, cat)

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: output}},
	}, FindToolsOutput{Result: output}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "find_tools",
		Description: `Discovers installed development tools (compilers, build systems, runtimes) on the system.
Returns paths and versions for: Go, .NET/MSBuild, Node.js, Python, Java, Rust, C/C++ (GCC/Clang/MSVC), CMake, Make, Git, Docker, Bun, Deno.
Use this before running build commands to avoid PATH issues.
Searches environment variables, PATH, and known installation directories.`,
	}, Handle)
}

func formatResults(results []ToolInfo, category string) string {
	var sb strings.Builder
	sb.WriteString("=== Development Tools ===\n")

	// Group by category
	grouped := make(map[string][]ToolInfo)
	for _, r := range results {
		cat := categoryOf(r.Name)
		grouped[cat] = append(grouped[cat], r)
	}

	found := 0
	notFound := 0

	for _, cat := range CategoryOrder {
		tools, ok := grouped[cat]
		if !ok {
			continue
		}

		label := CategoryLabel[cat]
		if label == "" {
			label = cat
		}
		sb.WriteString(fmt.Sprintf("\n[%s]\n", label))

		for _, t := range tools {
			if t.Path != "" {
				ver := ""
				if t.Version != "" {
					ver = fmt.Sprintf(" (%s)", t.Version)
				}
				sb.WriteString(fmt.Sprintf("  %s: %s%s\n", t.Name, t.Path, ver))
				found++
			} else {
				sb.WriteString(fmt.Sprintf("  %s: not found\n", t.Name))
				notFound++
			}
		}
	}

	// Special tools not belonging to any category (cl, py launcher)
	var uncategorized []ToolInfo
	for _, r := range results {
		if categoryOf(r.Name) == "" {
			uncategorized = append(uncategorized, r)
		}
	}
	for _, t := range uncategorized {
		if t.Path != "" {
			ver := ""
			if t.Version != "" {
				ver = fmt.Sprintf(" (%s)", t.Version)
			}
			sb.WriteString(fmt.Sprintf("  %s: %s%s\n", t.Name, t.Path, ver))
			found++
		}
	}

	sb.WriteString(fmt.Sprintf("\nFound: %d tools | Not found: %d tools\n", found, notFound))

	return sb.String()
}

// categoryOf returns the category for a tool name.
func categoryOf(name string) string {
	for _, def := range Catalog() {
		if def.Name == name {
			return def.Category
		}
	}
	// Special tools
	switch {
	case strings.Contains(name, "MSVC"):
		return "c_cpp"
	case strings.Contains(name, "py"):
		return "python"
	}
	return ""
}

func errorResult(msg string) (*mcp.CallToolResult, FindToolsOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, FindToolsOutput{Result: msg}, nil
}
