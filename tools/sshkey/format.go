package sshkey

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/argon2"
	gossh "golang.org/x/crypto/ssh"
)

const (
	ppkArgonMemory      = 8192
	ppkArgonPasses      = 13
	ppkArgonParallelism = 1
	ppkSaltSize         = 16
	ppkDerivedKeySize   = 32 + aes.BlockSize + 32
)

func marshalPrivateKey(key any, format, passphrase, comment string) ([]byte, error) {
	switch format {
	case "ppk":
		secret := []byte(passphrase)
		defer clear(secret)
		return marshalPPKv3(key, secret, comment)
	case "openssh":
		var (
			block *pem.Block
			err   error
		)
		if passphrase == "" {
			block, err = gossh.MarshalPrivateKey(key, comment)
		} else {
			secret := []byte(passphrase)
			defer clear(secret)
			block, err = gossh.MarshalPrivateKeyWithPassphrase(key, comment, secret)
		}
		if err != nil {
			return nil, fmt.Errorf("cannot encode OpenSSH private key: %w", err)
		}
		return pem.EncodeToMemory(block), nil
	case "pem":
		if passphrase != "" {
			return nil, fmt.Errorf("output_passphrase is supported only for ppk and openssh output; legacy PEM encryption is intentionally not generated")
		}
		return marshalPEM(key)
	case "pkcs8":
		if passphrase != "" {
			return nil, fmt.Errorf("output_passphrase is supported only for ppk and openssh output")
		}
		return marshalPKCS8(key)
	default:
		return nil, fmt.Errorf("unsupported output_format %q (supported: ppk, pem, openssh, pkcs8)", format)
	}
}

func marshalPEM(key any) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("invalid RSA private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("cannot encode EC private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	case *dsa.PrivateKey:
		der, err := asn1.Marshal(struct {
			Version       int
			P, Q, G, Y, X *big.Int
		}{0, k.P, k.Q, k.G, k.Y, k.X})
		if err != nil {
			return nil, fmt.Errorf("cannot encode DSA private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: der}), nil
	case ed25519.PrivateKey:
		return marshalPKCS8(k)
	case *ed25519.PrivateKey:
		return marshalPKCS8(*k)
	default:
		return nil, fmt.Errorf("PEM output does not support private key type %T", key)
	}
}

func marshalPKCS8(key any) ([]byte, error) {
	if k, ok := key.(*ed25519.PrivateKey); ok {
		key = *k
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("cannot encode PKCS#8 private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func marshalPPKv3(key any, passphrase []byte, comment string) ([]byte, error) {
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("cannot derive SSH public key: %w", err)
	}
	algorithm := signer.PublicKey().Type()
	publicBlob := signer.PublicKey().Marshal()
	privateBlob, err := marshalPPKPrivateBlob(key)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(comment, "\r\n") {
		return nil, fmt.Errorf("comment must not contain CR or LF characters")
	}
	if comment == "" {
		comment = "agent-tool"
	}

	encryption := "none"
	storedPrivate := privateBlob
	macKey := []byte(nil)
	var kdfHeaders string
	if len(passphrase) > 0 {
		encryption = "aes256-cbc"
		padding := make([]byte, aes.BlockSize-len(privateBlob)%aes.BlockSize)
		if _, err := rand.Read(padding); err != nil {
			return nil, fmt.Errorf("cannot generate PPK padding: %w", err)
		}
		plainPrivate := append(append([]byte(nil), privateBlob...), padding...)
		salt := make([]byte, ppkSaltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("cannot generate PPK salt: %w", err)
		}
		derived := argon2.IDKey(passphrase, salt, ppkArgonPasses, ppkArgonMemory, ppkArgonParallelism, ppkDerivedKeySize)
		defer clear(derived)
		block, err := aes.NewCipher(derived[:32])
		if err != nil {
			return nil, fmt.Errorf("cannot initialize PPK cipher: %w", err)
		}
		storedPrivate = append([]byte(nil), plainPrivate...)
		cipher.NewCBCEncrypter(block, derived[32:32+aes.BlockSize]).CryptBlocks(storedPrivate, storedPrivate)
		macKey = derived[32+aes.BlockSize:]
		privateBlob = plainPrivate
		kdfHeaders = fmt.Sprintf("Key-Derivation: Argon2id\nArgon2-Memory: %d\nArgon2-Passes: %d\nArgon2-Parallelism: %d\nArgon2-Salt: %s\n",
			ppkArgonMemory, ppkArgonPasses, ppkArgonParallelism, hex.EncodeToString(salt))
	}

	macData := gossh.Marshal(struct {
		Algorithm, Encryption, Comment string
		Public, Private                []byte
	}{algorithm, encryption, comment, publicBlob, privateBlob})
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(macData)

	publicText, publicLines := splitBase64(publicBlob)
	privateText, privateLines := splitBase64(storedPrivate)
	var out bytes.Buffer
	fmt.Fprintf(&out, "PuTTY-User-Key-File-3: %s\n", algorithm)
	fmt.Fprintf(&out, "Encryption: %s\n", encryption)
	fmt.Fprintf(&out, "Comment: %s\n", comment)
	fmt.Fprintf(&out, "Public-Lines: %d\n%s", publicLines, publicText)
	out.WriteString(kdfHeaders)
	fmt.Fprintf(&out, "Private-Lines: %d\n%s", privateLines, privateText)
	fmt.Fprintf(&out, "Private-MAC: %s\n", hex.EncodeToString(mac.Sum(nil)))
	return out.Bytes(), nil
}

func marshalPPKPrivateBlob(key any) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if len(k.Primes) != 2 {
			return nil, fmt.Errorf("PPK supports RSA keys with exactly two prime factors")
		}
		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("invalid RSA private key: %w", err)
		}
		p, q := k.Primes[0], k.Primes[1]
		if p.Cmp(q) < 0 {
			p, q = q, p
		}
		qInv := new(big.Int).ModInverse(q, p)
		if qInv == nil {
			return nil, fmt.Errorf("cannot compute RSA CRT coefficient")
		}
		return gossh.Marshal(struct{ D, P, Q, QInv *big.Int }{k.D, p, q, qInv}), nil
	case *dsa.PrivateKey:
		return gossh.Marshal(struct{ X *big.Int }{k.X}), nil
	case *ecdsa.PrivateKey:
		return gossh.Marshal(struct{ D *big.Int }{k.D}), nil
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid Ed25519 private key length: %d", len(k))
		}
		seed := k.Seed()
		return gossh.Marshal(struct{ Seed []byte }{seed}), nil
	case *ed25519.PrivateKey:
		return marshalPPKPrivateBlob(ed25519.PrivateKey(*k))
	default:
		return nil, fmt.Errorf("PPK output does not support private key type %T", key)
	}
}

func splitBase64(data []byte) (string, int) {
	encoded := base64.StdEncoding.EncodeToString(data)
	if encoded == "" {
		return "", 0
	}
	var out strings.Builder
	lines := 0
	for len(encoded) > 0 {
		n := 64
		if len(encoded) < n {
			n = len(encoded)
		}
		out.WriteString(encoded[:n])
		out.WriteByte('\n')
		encoded = encoded[n:]
		lines++
	}
	return out.String(), lines
}
