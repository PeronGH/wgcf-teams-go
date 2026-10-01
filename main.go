// Command wgcf-teams-go registers a device with Cloudflare WARP for Teams
// (Zero Trust) and prints a WireGuard or MASQUE configuration for it.
package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/browser"
)

func main() {
	var prompt, masque bool
	flag.BoolVar(&prompt, "p", false, "prompt for a private key instead of generating one")
	flag.BoolVar(&prompt, "prompt", false, "prompt for a private key instead of generating one")
	flag.BoolVar(&masque, "m", false, "register a MASQUE tunnel and print a usque config.json")
	flag.BoolVar(&masque, "masque", false, "register a MASQUE tunnel and print a usque config.json")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-p] [-m] <team-name>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(flag.Arg(0), prompt, masque); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(team string, prompt, masque bool) error {
	if !validTeamName(team) {
		return fmt.Errorf("invalid team name: %q", team)
	}
	stdin := bufio.NewReader(os.Stdin)

	newKey := newWireGuardKey
	if masque {
		newKey = newMASQUEKey
	}
	key, err := newKey(stdin, prompt)
	if err != nil {
		return err
	}
	token, err := getJWTToken(stdin, team)
	if err != nil {
		return fmt.Errorf("failed to get jwt token: %w", err)
	}

	result, err := register(key.publicKey, key.keyType, key.tunnelType, token)
	if err != nil {
		return err
	}
	profile, err := key.profile(result)
	if err != nil {
		return err
	}

	fmt.Print(profile)
	return nil
}

// tunnelKey is a local tunnel key together with how to enroll it and how
// to render the resulting registration.
type tunnelKey struct {
	publicKey  string // base64, in the encoding key_type requires
	keyType    string
	tunnelType string
	profile    func(*registrationResult) (string, error)
}

func newWireGuardKey(stdin *bufio.Reader, prompt bool) (*tunnelKey, error) {
	privkey, err := getWGPrivkey(stdin, prompt)
	if err != nil {
		return nil, err
	}
	return &tunnelKey{
		publicKey:  base64.StdEncoding.EncodeToString(privkey.PublicKey().Bytes()),
		keyType:    "curve25519",
		tunnelType: "wireguard",
		profile: func(r *registrationResult) (string, error) {
			c, err := r.toWGConfig(privkey)
			if err != nil {
				return "", err
			}
			return c.String(), nil
		},
	}, nil
}

func newMASQUEKey(stdin *bufio.Reader, prompt bool) (*tunnelKey, error) {
	privkey, err := getMASQUEPrivkey(stdin, prompt)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&privkey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}
	return &tunnelKey{
		publicKey:  base64.StdEncoding.EncodeToString(spki),
		keyType:    "secp256r1",
		tunnelType: "masque",
		profile: func(r *registrationResult) (string, error) {
			c, err := r.toUsqueConfig(privkey)
			if err != nil {
				return "", err
			}
			out, err := json.MarshalIndent(c, "", "  ")
			if err != nil {
				return "", err
			}
			fmt.Fprintf(os.Stderr, "Connect with usque using -s %s", masqueSNI)
			if c.Port != 443 {
				fmt.Fprintf(os.Stderr, " -P %d", c.Port)
			}
			fmt.Fprintln(os.Stderr)
			return string(out) + "\n", nil
		},
	}, nil
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

// getMASQUEPrivkey generates a P-256 key, or reads one in usque's encoding:
// base64 of the SEC 1 DER private key.
func getMASQUEPrivkey(stdin *bufio.Reader, prompt bool) (*ecdsa.PrivateKey, error) {
	if !prompt {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	fmt.Fprintln(os.Stderr, "Paste your base64 SEC 1 DER P-256 private key and press enter:")
	line, err := stdin.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read from stdin: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil {
		return nil, fmt.Errorf("failed to parse masque private key: %w", err)
	}
	privkey, err := x509.ParseECPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse masque private key: %w", err)
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
