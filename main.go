// Command wgcf-teams extracts WireGuard configurations from Cloudflare's
// WARP for Teams. It is a Go port of https://github.com/poscat0x04/wgcf-teams.
package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
)

const instructionURL = "https://github.com/PeronGH/wgcf-teams-go/blob/main/guide.md"

func main() {
	var prompt bool
	flag.BoolVar(&prompt, "p", false, "prompt for wireguard private key instead of randomly generating one")
	flag.BoolVar(&prompt, "prompt", false, "prompt for wireguard private key instead of randomly generating one")
	flag.Parse()

	if err := run(prompt); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(prompt bool) error {
	stdin := bufio.NewReader(os.Stdin)

	privkey, err := getWGPrivkey(stdin, prompt)
	if err != nil {
		return err
	}
	token, err := getJWTToken(stdin)
	if err != nil {
		return fmt.Errorf("failed to get jwt token: %w", err)
	}

	wgConfig, err := register(privkey, token)
	if err != nil {
		return err
	}

	fmt.Println(wgConfig)
	return nil
}

func getWGPrivkey(stdin *bufio.Reader, prompt bool) (*ecdh.PrivateKey, error) {
	if !prompt {
		return ecdh.X25519().GenerateKey(rand.Reader)
	}
	fmt.Fprintln(os.Stderr, "Please paste your wireguard private key and press enter:")
	line, err := stdin.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read from stdin: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil {
		return nil, fmt.Errorf("failed to parse wireguard private key: %w", err)
	}
	privkey, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wireguard private key: %w", err)
	}
	return privkey, nil
}

func getJWTToken(stdin *bufio.Reader) (string, error) {
	fmt.Fprintln(os.Stderr, "Please open https://<YOUR_ORGANIZATION>.cloudflareaccess.com/warp, log in to warp, paste the JWT token here and press enter.")
	fmt.Fprintf(os.Stderr, "For a detailed instruction on where to find the JWT token after login, see %s.\n", instructionURL)
	return stdin.ReadString('\n')
}
