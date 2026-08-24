package proclist

import (
	"strings"
	"testing"
)

func TestSanitizeOutputPreservesLayoutAndMasksSecrets(t *testing.T) {
	input := "before  aligned\n--password hunter2\nTOKEN=abc123\n--api-key=xyz\nBearer\nbearer-secret\n--secret\n'quoted-secret'\nafter\n"
	got := SanitizeOutput(input)
	want := "before  aligned\n--password ***\nTOKEN=***\n--api-key=***\nBearer\n***\n--secret\n***\nafter\n"
	if got != want {
		t.Fatalf("sanitize output\n got: %q\nwant: %q", got, want)
	}
	for _, secret := range []string{"hunter2", "abc123", "xyz", "bearer-secret", "quoted-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q was not masked: %q", secret, got)
		}
	}
}

func TestSanitizeCommandLineStillNormalizesWhitespace(t *testing.T) {
	got := SanitizeCommandLine("tool   --token secret\n--flag value")
	if got != "tool --token *** --flag value" {
		t.Fatalf("unexpected command line: %q", got)
	}
}

func TestSanitizeCommandLineCoversLegacySecretForms(t *testing.T) {
	input := `curl https://user:url-secret@example.com -H "Authorization: Bearer bearer-secret" --password "quoted secret" --auth='inline-quoted' PASSWD=env-secret --token=equal-secret ssh -p 22`
	got := SanitizeCommandLine(input)
	for _, secret := range []string{"url-secret", "bearer-secret", "quoted secret", "inline-quoted", "env-secret", "equal-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q was not masked: %q", secret, got)
		}
	}
	if !strings.Contains(got, "ssh -p 22") {
		t.Fatalf("non-sensitive ssh port was altered: %q", got)
	}
}
