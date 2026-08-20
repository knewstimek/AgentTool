package debug

import "testing"

func TestNormalizeDebugOutputLimits(t *testing.T) {
	in := DebugInput{}
	if err := normalizeDebugOutputLimits(&in); err != nil {
		t.Fatal(err)
	}
	if in.MaxResults != defaultDebugMaxResults || in.MaxValueChars != defaultDebugMaxValueChars || in.MaxOutputChars != defaultDebugMaxOutputChars {
		t.Fatalf("defaults not applied: %+v", in)
	}

	in = DebugInput{MaxResults: hardDebugMaxResults + 1}
	if err := normalizeDebugOutputLimits(&in); err == nil {
		t.Fatal("runaway result limit should be rejected")
	}
}
