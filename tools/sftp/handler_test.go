package sftp

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestUploadManyRequiresBoundedItemsBeforeConnecting(t *testing.T) {
	result, _, err := Handle(context.Background(), nil, SFTPInput{
		Operation: "upload_many", Host: "127.0.0.1", User: "test", Password: "not-used",
	})
	if err != nil || !result.IsError {
		t.Fatalf("expected validation error: result=%v err=%v", result, err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "uploads must contain") {
		t.Fatalf("unexpected error: %s", text)
	}
}
