// Command wgcf-teams-go registers a device with Cloudflare WARP for Teams
// (Zero Trust) and prints a WireGuard configuration for it.
package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/browser"
)

func main() {
	var prompt bool
	flag.BoolVar(&prompt, "p", false, "prompt for a wireguard private key instead of generating one")
	flag.BoolVar(&prompt, "prompt", false, "prompt for a wireguard private key instead of generating one")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-p] <team-name>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(flag.Arg(0), prompt); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(team string, prompt bool) error {
	if !validTeamName(team) {
		return fmt.Errorf("invalid team name: %q", team)
	}
	stdin := bufio.NewReader(os.Stdin)

	privkey, err := getWGPrivkey(stdin, prompt)
	if err != nil {
		return err
	}
	token, err := getJWTToken(stdin, team)
	if err != nil {
		return fmt.Errorf("failed to get jwt token: %w", err)
	}

	wgConfig, err := register(privkey, token)
	if err != nil {
		return err
	}

	fmt.Print(wgConfig)
	return nil
}

// validTeamName reports whether s can be a Zero Trust team name
// (a subdomain label of cloudflareaccess.com).
func validTeamName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		valid := r == '-' ||
			'a' <= r && r <= 'z' ||
			'A' <= r && r <= 'Z' ||
			'0' <= r && r <= '9'
		if !valid {
			return false
		}
	}
	return true
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

func getJWTToken(stdin *bufio.Reader, team string) (string, error) {
	loginURL := "https://" + team + ".cloudflareaccess.com/warp"
	fmt.Fprintf(os.Stderr, "Opening %s — log in there.\n", loginURL)
	if err := browser.OpenURL(loginURL); err != nil {
		fmt.Fprintf(os.Stderr, "(could not open a browser: %v; open the URL manually)\n", err)
	}
	fmt.Fprintln(os.Stderr, "After login, open the browser console (F12) on the success page and run:")
	fmt.Fprintln(os.Stderr, "  copy(document.getElementById('redirect-button').getAttribute('onclick'))")
	fmt.Fprintln(os.Stderr, "That puts the login callback on your clipboard; paste it here within 60 seconds and press enter:")
	line, err := stdin.ReadString('\n')
	if err != nil {
		return "", err
	}
	return extractToken(line)
}

// extractToken pulls the JWT out of whatever was pasted: a bare token, the
// com.cloudflare.warp:// callback URL, or the login page's whole redirect
// onclick attribute containing that URL.
func extractToken(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", errors.New("no token provided")
	}
	if i := strings.Index(input, "token="); i >= 0 {
		token := input[i+len("token="):]
		if j := strings.IndexFunc(token, func(r rune) bool { return !isJWTChar(r) }); j >= 0 {
			token = token[:j]
		}
		if token != "" {
			return token, nil
		}
	}
	return input, nil
}

func isJWTChar(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' ||
		r == '.' || r == '_' || r == '-'
}
