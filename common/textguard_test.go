package common

import (
	"strings"
	"testing"
	"unicode/utf8"
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
	if !strings.Contains(got, "of 300 runes") {
		t.Errorf("truncation did not report the total: %q", got)
	}
	if n := len([]rune(got)); n > maxEchoRunes+24 {
		t.Errorf("truncated to %d runes, want near %d", n, maxEchoRunes)
	}
}

// Cutting on a rune boundary alone would show a character that was never
// written -- a family emoji reduced to one person, a flag to a bare letter --
// which is the exact failure this echo exists to expose.
func TestTruncateKeepsGraphemesIntact(t *testing.T) {
	cases := []struct {
		name    string
		tail    string
		partial []string // fragments that must never appear alone at the cut
	}{
		{"zwj family", "👨‍👩‍👧", []string{"👨‍", "👨..."}},
		{"regional flag", "🇰🇷", []string{"🇰..."}},
		{"combining mark", "é", []string{}},
		{"variation selector", "⚠️", []string{"⚠..."}},
	}
	for _, c := range cases {
		// Sweep the cut across the cluster: some offset lands mid-cluster.
		for pad := 95; pad <= 101; pad++ {
			in := strings.Repeat("가", pad) + " " + c.tail + strings.Repeat("나", 40)
			got := NonASCIIEcho(in)
			for _, frag := range c.partial {
				if strings.Contains(got, frag) {
					t.Errorf("%s (pad=%d): cluster split, got %q", c.name, pad, got)
				}
			}
			if !utf8.ValidString(got) {
				t.Errorf("%s (pad=%d): invalid UTF-8 out", c.name, pad)
			}
		}
	}
}

// A minified line is one space-free "word": echoing it whole spends the cap on
// ASCII and pushes out the text that actually needs checking.
func TestLongWordCondensed(t *testing.T) {
	in := `var cfg={mode:"prod",label:"설정",retries:3,timeoutMs:15000,endpoint:"/api/v1/things",fallback:"none"};`
	got := NonASCIIEcho(in)
	if !strings.Contains(got, "설정") {
		t.Fatalf("lost the non-ASCII content: %q", got)
	}
	if strings.Contains(got, "timeoutMs") || strings.Contains(got, "fallback") {
		t.Errorf("echoed unrelated ASCII: %q", got)
	}
	if n := len([]rune(got)); n > 24 {
		t.Errorf("condensed form is %d runes, want small: %q", n, got)
	}
}

// Characters that render as a space or as nothing cannot be checked by looking
// at them, so they are counted instead.
func TestInvisibleCharNotice(t *testing.T) {
	if got := InvisibleCharNotice("plain 텍스트 ok"); got != "" {
		t.Errorf("clean text reported: %q", got)
	}

	nbsp := InvisibleCharNotice("if (a == b) { return 1; }")
	if !strings.Contains(nbsp, "U+00A0") || !strings.Contains(nbsp, "1 x") {
		t.Errorf("NBSP not reported: %q", nbsp)
	}

	ideo := InvisibleCharNotice("サーバー　再起動　開始")
	if !strings.Contains(ideo, "2 x U+3000") {
		t.Errorf("ideographic space not counted: %q", ideo)
	}

	zwsp := InvisibleCharNotice("보이지​않는")
	if !strings.Contains(zwsp, "U+200B") {
		t.Errorf("ZWSP not reported: %q", zwsp)
	}

	// ZWJ is load-bearing in emoji sequences; flagging it would fire on every
	// family or profession emoji.
	if got := InvisibleCharNotice("done 👨‍👩‍👧 ok"); got != "" {
		t.Errorf("ZWJ inside emoji reported: %q", got)
	}
}

// A no-break space is invisible to the echo but must not vanish entirely.
func TestNBSPIsNotSilent(t *testing.T) {
	notice := TextGuardNotice("if (a == b) { return 1; }")
	if notice == "" {
		t.Fatal("a stray NBSP produced no notice at all")
	}
	if !strings.Contains(notice, "U+00A0") {
		t.Errorf("notice does not name the character: %q", notice)
	}
}

func TestReplacementCharCount(t *testing.T) {
	if n, line := ReplacementCharCount("clean"); n != 0 || line != 0 {
		t.Errorf("clean text = (%d, %d), want (0, 0)", n, line)
	}
	n, line := ReplacementCharCount("a\nb�c\n�")
	if n != 2 || line != 2 {
		t.Errorf("got (%d, %d), want (2, 2)", n, line)
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
