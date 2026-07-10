// notetool: sign/verify C2SP signed notes with the Go reference implementation.
//
// Usage:
//   notetool sign   <name> <seed-hex>       (body on stdin; signed note on stdout)
//   notetool verify <verifier-key>          (note on stdin; verified body on stdout)
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/mod/sumdb/note"
)

func keyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: notetool sign|verify ...")
		os.Exit(2)
	}
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read stdin:", err)
		os.Exit(1)
	}
	switch os.Args[1] {
	case "sign":
		name, seedHex := os.Args[2], os.Args[3]
		seed, err := hex.DecodeString(seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			fmt.Fprintln(os.Stderr, "bad seed")
			os.Exit(1)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pubkey := append([]byte{1}, priv[32:]...)
		skey := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, keyHash(name, pubkey),
			base64.StdEncoding.EncodeToString(append([]byte{1}, seed...)))
		signer, err := note.NewSigner(skey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "NewSigner:", err)
			os.Exit(1)
		}
		msg, err := note.Sign(&note.Note{Text: string(stdin)}, signer)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Sign:", err)
			os.Exit(1)
		}
		os.Stdout.Write(msg)
	case "verify":
		vkey := os.Args[2]
		verifier, err := note.NewVerifier(vkey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "NewVerifier:", err)
			os.Exit(1)
		}
		n, err := note.Open(stdin, note.VerifierList(verifier))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Open:", err)
			os.Exit(1)
		}
		os.Stdout.WriteString(n.Text)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode")
		os.Exit(2)
	}
}
