package common

import (
	"strings"
	"testing"
)

func TestNonASCIIEcho(t *testing.T) {
	// The check is a codepoint range, not a script list: every language that
	// leaves ASCII has to come back readable, or this is a Korean-only tool.
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"pure ascii", "func main() { return nil }", ""},
		{"korean", "설정 값", "설정 값"},
		{"japanese", "サーバー再起動", "サーバー再起動"},
		{"chinese", "服务器 重新启动", "服务器 重新启动"},
		{"cyrillic", "перезапуск сервера", "перезапуск сервера"},
		{"arabic", "إعادة تشغيل", "إعادة تشغيل"},
		{"greek", "επανεκκίνηση", "επανεκκίνηση"},
		// Latin scripts mix ASCII and non-ASCII inside one word -- the whole
		// word must survive, not the accented letter alone.
		{"french", "le café au lait", "café"},
		{"german", "Grüße aus München", "Grüße, München"},
		{"spanish", "el niño pequeño", "niño pequeño"},
		{"emoji", "status ✅ done", "✅"},
		{"runs split by code", `msg := "설정 값" + suffix + "재시작"`, `"설정 값", "재시작"`},
		{"newline separates", "첫째 줄\n둘째 줄", "첫째 줄, 둘째 줄"},
		{"ascii word ends run", "값 = x", "값"},
	}
	for _, c := range cases {
		if got := NonASCIIEcho(c.in); got != c.want {
			t.Errorf("%s: NonASCIIEcho(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// A bulk translation must not drag its whole payload into the response.
func TestNonASCIIEchoTruncates(t *testing.T) {
	long := strings.Repeat("가나다라마", 60) // 300 runes
	got := NonASCIIEcho(long)
	if !strings.HasSuffix(got, "...") {
		t.Errorf("long input was not truncated: %q", got)
	}
	if n := len([]rune(got)); n > maxEchoRunes+3 {
		t.Errorf("truncated to %d runes, want <= %d", n, maxEchoRunes+3)
	}
}

func TestReplacementCharWarning(t *testing.T) {
	if got := ReplacementCharWarning("clean 텍스트\nsecond line"); got != "" {
		t.Errorf("clean text warned: %q", got)
	}

	got := ReplacementCharWarning("line one\nline two 한�글\nline three")
	if got == "" {
		t.Fatal("U+FFFD not reported")
	}
	if !strings.Contains(got, "line 2") {
		t.Errorf("wrong line reported: %q", got)
	}
	if !strings.Contains(got, "1 replacement char") {
		t.Errorf("wrong count reported: %q", got)
	}

	multi := ReplacementCharWarning("���")
	if !strings.Contains(multi, "3 replacement char") {
		t.Errorf("wrong count for 3: %q", multi)
	}
}

func TestTextGuardNotice(t *testing.T) {
	if got := TextGuardNotice("plain ascii only"); got != "" {
		t.Errorf("ascii produced a notice: %q", got)
	}
	notice := TextGuardNotice(`x := "설정 값"`)
	if !strings.Contains(notice, `non-ASCII written: "설정 값"`) {
		t.Errorf("missing echo: %q", notice)
	}
	if strings.Contains(notice, "U+FFFD") {
		t.Errorf("clean text warned about corruption: %q", notice)
	}
}
