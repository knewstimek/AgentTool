package toolbox

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestProfilesStayCompactAndComposable(t *testing.T) {
	if groups, ok := profileGroups("core"); !ok || len(groups) != 1 || groups[0] != "core" {
		t.Fatalf("core profile = %v, %v", groups, ok)
	}
	if groups, ok := profileGroups("remote"); !ok || len(groups) != 2 {
		t.Fatalf("remote profile = %v, %v", groups, ok)
	}
	if _, ok := profileGroups("everything-ish"); ok {
		t.Fatal("unknown profile was accepted")
	}
}

func TestManagerEnablesOnlyRequestedGroup(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	registered := map[string]int{}
	m := NewManager(server, []Spec{
		{Name: "read", Group: "core", Register: func() { registered["read"]++ }},
		{Name: "ssh", Group: "remote", Register: func() { registered["ssh"]++ }},
	})
	if err := m.EnableProfile("core"); err != nil {
		t.Fatal(err)
	}
	if registered["read"] != 1 || registered["ssh"] != 0 {
		t.Fatalf("registered = %#v", registered)
	}
	if err := m.EnableProfile("core"); err != nil || registered["read"] != 1 {
		t.Fatalf("duplicate enable = %#v, %v", registered, err)
	}
}
