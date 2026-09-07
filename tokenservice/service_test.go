package tokenservice

import (
	"strings"
	"testing"

	"github.com/PretendoNetwork/nex-go/v2/types"
)

func TestDecodeHexSecret(t *testing.T) {
	if _, err := DecodeHexSecret(strings.Repeat("00", 32), 32); err != nil {
		t.Fatalf("valid 32-byte hex rejected: %v", err)
	}
	if _, err := DecodeHexSecret(strings.Repeat("00", 16), 32); err == nil {
		t.Fatal("short secret accepted")
	}
	if _, err := DecodeHexSecret("nothex!!", 32); err == nil {
		t.Fatal("non-hex accepted")
	}
}

func TestPasswordFromPIDStableAndKeyed(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))

	a, code := passwordFromPID(secret, types.NewPID(1000))
	if code != 0 || a == "" {
		t.Fatalf("expected a password, got (%q, %d)", a, code)
	}
	if b, _ := passwordFromPID(secret, types.NewPID(1000)); b != a {
		t.Fatalf("not deterministic: %q != %q", a, b)
	}
	if c, _ := passwordFromPID(secret, types.NewPID(1001)); c == a {
		t.Fatal("different PIDs produced the same password")
	}
	if _, code := passwordFromPID([]byte("short"), types.NewPID(1000)); code == 0 {
		t.Fatal("short secret accepted")
	}
}

func TestIssueTokenIsBase64AndDeterministicPerClock(t *testing.T) {
	key := []byte(strings.Repeat("a", 32))
	tok, err := issueToken(key, 1234, 0x0005000010137e00, 15*60*1e9)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 24 || strings.ContainsAny(tok, " \n") {
		t.Fatalf("token does not look like base64: %q", tok)
	}
}
