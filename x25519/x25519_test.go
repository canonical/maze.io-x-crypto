package x25519

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	p, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("GenerateKey returned nil")
	}
}

// testVectors from RFC 7748 section 6.1
var testVectors = []struct {
	A *PrivateKey
	B *PublicKey
	S []byte
}{
	{
		A: secretHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
		B: publicHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
		S: unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
	},
	{
		A: secretHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
		B: publicHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
		S: unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
	},
}

func TestECDH(t *testing.T) {
	for _, vectors := range testVectors {
		t.Run("", func(t *testing.T) {
			if !bytes.Equal(vectors.S, vectors.A.Shared(vectors.B)) {
				t.Fail()
			}
		})
	}
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func secretHex(s string) *PrivateKey {
	secret := new(PrivateKey)
	copy(secret.b[:], unhex(s))
	return secret
}

func publicHex(s string) *PublicKey {
	public := new(PublicKey)
	copy(public.b[:], unhex(s))
	return public
}
