package common

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SafeAddTool wraps mcp.AddTool with panic recovery so that an unexpected
// panic inside a tool handler does not crash the entire MCP server process.
// Instead the panic is caught, logged to stderr, and returned as an error
// result to the client.
func SafeAddTool[In, Out any](s *mcp.Server, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	toolName := t.Name
	wrapped := func(ctx context.Context, req *mcp.CallToolRequest, input In) (result *mcp.CallToolResult, output Out, err error) {
		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()
				log.Printf("PANIC in tool %q: %v\n%s", toolName, r, stack)
				result = &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{
						// Don't expose panic value to client; it may contain
						// sensitive info (e.g. DB connection strings).
						// Full details are in the server stderr log above.
						Text: fmt.Sprintf("internal error: panic in %s (see server logs)", toolName),
					}},
					IsError: true,
				}
				var zero Out
				output = zero
			}
		}()
		return h(ctx, req, input)
	}
	mcp.AddTool(s, t, wrapped)
}
