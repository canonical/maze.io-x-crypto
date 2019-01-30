package afis

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

var testVectors = []struct {
	data    []byte
	stripes int
}{
	{[]byte(""), 1},
	{[]byte(""), 2},
	{[]byte("Look, it's Gophers everywhere!"), 1},
	{[]byte("Look, it's Gophers everywhere!"), 2},
	{[]byte("Look, it's Gophers everywhere!"), 4},
	{[]byte("Look, it's Gophers everywhere!"), 8},
}

func TestAFIS(t *testing.T) {
	for _, vector := range testVectors {
		t.Run("", func(t *testing.T) {
			splitted, err := Split(vector.data, vector.stripes)
			if err != nil {
				t.Fatal(err)
			}

			merged, err := Merge(splitted, vector.stripes)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(merged, vector.data) {
				t.Fatalf("expected %q, got %q", vector.data, merged)
			}
		})
	}
}

func ExampleMerge() {
	secretKey := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, secretKey); err != nil {
		panic(err)
	}

	// Split the original data using 4 stripes.
	scrambled, err := Split(secretKey, 4)
	if err != nil {
		panic(err)
	}

	// Merge back
	key, err := Merge(scrambled, 4)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(key, secretKey) {
		panic("merge failed")
	}
}
