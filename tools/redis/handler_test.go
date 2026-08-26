package redis

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	goredis "github.com/redis/go-redis/v9"
)

func TestRedisTLSUsesRequestedHostForVerification(t *testing.T) {
	input := RedisInput{
		Host: "cache.example.com",
		TLS:  true,
	}
	opts := newRedisOptions(input, "192.0.2.10", defaultPort, 0, time.Second)
	if opts.Addr != "192.0.2.10:6379" {
		t.Fatalf("Addr = %q, want resolved address", opts.Addr)
	}
	if opts.TLSConfig == nil {
		t.Fatal("TLS configuration is nil")
	}
	if opts.TLSConfig.ServerName != input.Host {
		t.Fatalf("TLS ServerName = %q, want %q", opts.TLSConfig.ServerName, input.Host)
	}
}

func TestFormatResultBoundsValuesAndTotalOutput(t *testing.T) {
	cmd := goredis.NewCmd(context.Background())
	cmd.SetVal([]interface{}{
		strings.Repeat("가", 100),
		strings.Repeat("나", 100),
		strings.Repeat("다", 100),
		strings.Repeat("라", 100),
	})

	got := formatResult(cmd, 10, 50)
	if !utf8.ValidString(got) {
		t.Fatal("formatted Redis output is not valid UTF-8")
	}
	if utf8.RuneCountInString(got) > 50 {
		t.Fatalf("formatted output has %d characters, want at most 50", utf8.RuneCountInString(got))
	}
	if !strings.Contains(got, "Output truncated") {
		t.Fatalf("formatted output does not report truncation: %q", got)
	}
}

func TestFormatResultBoundsScalarValue(t *testing.T) {
	cmd := goredis.NewCmd(context.Background())
	cmd.SetVal(strings.Repeat("한", 100))

	got := formatResult(cmd, 10, 100)
	if !utf8.ValidString(got) || utf8.RuneCountInString(got) > 13 {
		t.Fatalf("scalar value was not bounded safely: %q", got)
	}
}
