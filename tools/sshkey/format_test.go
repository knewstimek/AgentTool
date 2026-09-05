package sshkey

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/kayrus/putty"
	gossh "golang.org/x/crypto/ssh"
)

func TestMarshalPPKv3RoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var dsaParameters dsa.Parameters
	if err := dsa.GenerateParameters(&dsaParameters, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	dsaKey := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: dsaParameters}}
	if err := dsa.GenerateKey(dsaKey, rand.Reader); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		key  any
	}{
		{"rsa", rsaKey},
		{"ecdsa", ecKey},
		{"ed25519", edKey},
		{"dsa", dsaKey},
	} {
		for _, passphrase := range []string{"", "correct horse battery staple"} {
			name := tc.name + "/plain"
			if passphrase != "" {
				name = tc.name + "/encrypted"
			}
			t.Run(name, func(t *testing.T) {
				encoded, err := marshalPPKv3(tc.key, []byte(passphrase), "round-trip")
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasPrefix(string(encoded), "PuTTY-User-Key-File-3: ") {
					t.Fatalf("not a PPK v3 file: %q", encoded[:min(64, len(encoded))])
				}
				parsed, err := putty.New(encoded)
				if err != nil {
					t.Fatalf("independent PPK parser rejected output: %v", err)
				}
				got, err := parsed.ParseRawPrivateKey([]byte(passphrase))
				if err != nil {
					t.Fatalf("cannot decrypt generated PPK: %v", err)
				}
				assertSamePublicKey(t, tc.key, got)
			})
		}
	}
}

func TestMarshalPrivateKeyFormats(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		format     string
		passphrase string
		blockType  string
	}{
		{"pem", "", "PRIVATE KEY"},
		{"pkcs8", "", "PRIVATE KEY"},
		{"openssh", "", "OPENSSH PRIVATE KEY"},
		{"openssh", "secret", "OPENSSH PRIVATE KEY"},
	} {
		t.Run(tc.format+"/"+tc.passphrase, func(t *testing.T) {
			encoded, err := marshalPrivateKey(key, tc.format, tc.passphrase, "test-key")
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(encoded)
			if block == nil || block.Type != tc.blockType {
				t.Fatalf("PEM block type = %v, want %q", block, tc.blockType)
			}
			var got any
			if tc.passphrase == "" {
				got, err = gossh.ParseRawPrivateKey(encoded)
			} else {
				got, err = gossh.ParseRawPrivateKeyWithPassphrase(encoded, []byte(tc.passphrase))
			}
			if err != nil {
				t.Fatalf("cannot parse generated %s: %v", tc.format, err)
			}
			assertSamePublicKey(t, key, got)
		})
	}
}

func TestLegacyPEMRejectsOutputPassphrase(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = marshalPrivateKey(key, "pem", "secret", "")
	if err == nil || !strings.Contains(err.Error(), "only for ppk and openssh") {
		t.Fatalf("error = %v", err)
	}
}

func TestTraditionalPEMKeyTypes(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var parameters dsa.Parameters
	if err := dsa.GenerateParameters(&parameters, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	dsaKey := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: parameters}}
	if err := dsa.GenerateKey(dsaKey, rand.Reader); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		key       any
		blockType string
	}{
		{"rsa", rsaKey, "RSA PRIVATE KEY"},
		{"ecdsa", ecKey, "EC PRIVATE KEY"},
		{"dsa", dsaKey, "DSA PRIVATE KEY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := marshalPrivateKey(tc.key, "pem", "", "")
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(encoded)
			if block == nil || block.Type != tc.blockType {
				t.Fatalf("block type = %v, want %s", block, tc.blockType)
			}
			parsed, err := gossh.ParseRawPrivateKey(encoded)
			if err != nil {
				t.Fatalf("cannot parse generated PEM: %v", err)
			}
			assertSamePublicKey(t, tc.key, parsed)
		})
	}
}

func assertSamePublicKey(t *testing.T, wantKey, gotKey any) {
	t.Helper()
	want, err := gossh.NewSignerFromKey(wantKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gossh.NewSignerFromKey(gotKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(gossh.FingerprintSHA256(want.PublicKey()), gossh.FingerprintSHA256(got.PublicKey())) {
		t.Fatalf("public-key fingerprints differ: %s != %s", gossh.FingerprintSHA256(want.PublicKey()), gossh.FingerprintSHA256(got.PublicKey()))
	}
}
