// Command wgcf-teams-go registers a device with Cloudflare WARP for Teams
// (Zero Trust) and prints a WireGuard configuration for it.
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

func main() {
	var prompt bool
	flag.BoolVar(&prompt, "p", false, "prompt for a wireguard private key instead of generating one")
	flag.BoolVar(&prompt, "prompt", false, "prompt for a wireguard private key instead of generating one")
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
		return fmt.Errorf("failed to read jwt token: %w", err)
	}

	wgConfig, err := register(privkey, token)
	if err != nil {
		return err
	}

	fmt.Print(wgConfig)
	return nil
}

func getWGPrivkey(stdin *bufio.Reader, prompt bool) (*ecdh.PrivateKey, error) {
	if !prompt {
		return ecdh.X25519().GenerateKey(rand.Reader)
	}
	fmt.Fprintln(os.Stderr, "Paste your wireguard private key and press enter:")
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
	fmt.Fprintln(os.Stderr, "Open https://<your-team>.cloudflareaccess.com/warp and log in.")
	fmt.Fprintln(os.Stderr, `Then view the page source: <head> contains a <meta> tag with a long URL; copy the part after "?token=" (starts with "eyJ"). See the README for details.`)
	fmt.Fprintln(os.Stderr, "Paste the token here and press enter:")
	return stdin.ReadString('\n')
}
