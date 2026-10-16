package wgconf

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func hexToB64(t *testing.T, s string) string {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// RFC 7748 6.1
func TestDerivePublicKeyRFC7748(t *testing.T) {
	priv := hexToB64(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	want := hexToB64(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

	got, err := DerivePublicKey(priv)
	if err != nil {
		t.Fatalf("DerivePublicKey: %v", err)
	}
	if got != want {
		t.Errorf("public key = %s, want %s", got, want)
	}
}

func TestGenerateKeyPairDerivesBack(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	got, err := DerivePublicKey(priv)
	if err != nil {
		t.Fatalf("DerivePublicKey: %v", err)
	}
	if got != pub {
		t.Errorf("derived %s, want %s", got, pub)
	}
}

func TestGeneratePresharedKeyIs32RandomBytes(t *testing.T) {
	first, err := GeneratePresharedKey()
	if err != nil {
		t.Fatalf("GeneratePresharedKey: %v", err)
	}
	if raw, err := base64.StdEncoding.DecodeString(first); err != nil || len(raw) != 32 {
		t.Errorf("key %q decodes to %d bytes (err %v), want 32", first, len(raw), err)
	}
	second, err := GeneratePresharedKey()
	if err != nil {
		t.Fatalf("GeneratePresharedKey: %v", err)
	}
	if second == first {
		t.Errorf("two calls returned the same key %s", first)
	}
}

func TestDerivePublicKeyRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"bad base64", "not*base64!"},
		{"31-byte key", base64.StdEncoding.EncodeToString(make([]byte, 31))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := DerivePublicKey(tc.in); err == nil {
				t.Errorf("DerivePublicKey(%q) = %q, want error", tc.in, got)
			}
		})
	}
}
