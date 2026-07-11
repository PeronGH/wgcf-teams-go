package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const apiEndpoint = "https://zero-trust-client.cloudflareclient.com/v0i2308311933/reg"

const wgMTU = 1420

var (
	v4DNS = netip.MustParseAddr("1.1.1.1")
	v6DNS = netip.MustParseAddr("2606:4700:4700::1111")

	v4AllowedIPs = netip.MustParsePrefix("0.0.0.0/0")
	v6AllowedIPs = netip.MustParsePrefix("::/0")
)

type registration struct {
	Key         string `json:"key"`
	Tos         string `json:"tos"`
	Model       string `json:"model"`
	FCMToken    string `json:"fcm_token"`
	DeviceToken string `json:"device_token"`
}

func newRegistration(privkey *ecdh.PrivateKey) registration {
	return registration{
		Key:   base64.StdEncoding.EncodeToString(privkey.PublicKey().Bytes()),
		Tos:   time.Now().Format(time.RFC3339Nano),
		Model: "iPad13,8",
	}
}

// register posts a device registration to the Cloudflare API and converts the
// response into a WireGuard config.
func register(privkey *ecdh.PrivateKey, token string) (*wireGuardConfig, error) {
	body, err := json.Marshal(newRegistration(privkey))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize registration: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build request to cloudflare API: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cf-Access-Jwt-Assertion", strings.TrimSpace(token))
	req.Header.Set("CF-Client-Version", "i-6.23-2308311933.1")
	req.Header.Set("User-Agent", "1.1.1.1/6.23")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to cloudflare API failed: %w", err)
	}
	// The body is fully consumed before returning; the close error carries no information.
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read the response from cloudflare: %w", err)
	}
	var envelope cfResp[registrationResult]
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("unexpected response from cloudflare (HTTP %s): %.200s", resp.Status, raw)
	}
	result, err := envelope.getResult()
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	return result.Config.toWGConfig(privkey)
}

// cfResp is the envelope Cloudflare wraps every API response in.
type cfResp[T any] struct {
	Result   *T                `json:"result"`
	Errors   []json.RawMessage `json:"errors"`
	Messages []json.RawMessage `json:"messages"`
}

func (r cfResp[T]) getResult() (*T, error) {
	if r.Result == nil {
		return nil, &requestFailure{errors: r.Errors, messages: r.Messages}
	}
	return r.Result, nil
}

// requestFailure is a Cloudflare API response without a result.
type requestFailure struct {
	errors   []json.RawMessage
	messages []json.RawMessage
}

func (f *requestFailure) Error() string {
	var b strings.Builder
	b.WriteString("Request to Cloudflare API has failed with errors:\n")
	for _, e := range f.errors {
		fmt.Fprintf(&b, "\n%s\n", prettyJSON(e))
	}
	b.WriteString("\nAnd messages:\n")
	for _, m := range f.messages {
		fmt.Fprintf(&b, "\n%s\n", prettyJSON(m))
	}
	return b.String()
}

func prettyJSON(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

type registrationResult struct {
	Config warpConfig `json:"config"`
}

type warpConfig struct {
	ClientID  []byte     `json:"client_id"`
	Peers     []wgPeer   `json:"peers"`
	Interface wgIFConfig `json:"interface"`
}

type wgPeer struct {
	PublicKey []byte     `json:"public_key"`
	Endpoint  wgEndpoint `json:"endpoint"`
}

type wgEndpoint struct {
	Host string `json:"host"`
}

type wgIFConfig struct {
	Addresses ifAddrs `json:"addresses"`
}

type ifAddrs struct {
	V4 netip.Addr `json:"v4"`
	V6 netip.Addr `json:"v6"`
}

func (c *warpConfig) toWGConfig(privkey *ecdh.PrivateKey) (*wireGuardConfig, error) {
	if len(c.Peers) == 0 {
		return nil, fmt.Errorf("warp config contains no peers: %s", prettyJSON(mustMarshal(c)))
	}
	peer := c.Peers[0]
	if len(peer.PublicKey) != 32 {
		return nil, fmt.Errorf("peer public key is not 32 bytes: %q", base64.StdEncoding.EncodeToString(peer.PublicKey))
	}
	if len(c.ClientID) != 3 {
		return nil, fmt.Errorf("client id is not 3 bytes: %q", base64.StdEncoding.EncodeToString(c.ClientID))
	}
	if !c.Interface.Addresses.V4.Is4() || !c.Interface.Addresses.V6.Is6() {
		return nil, fmt.Errorf("unexpected interface address families: %s", prettyJSON(mustMarshal(c)))
	}

	return &wireGuardConfig{
		PrivateKey: privkey.Bytes(),
		IfAddresses: []netip.Prefix{
			netip.PrefixFrom(c.Interface.Addresses.V6, 128),
			netip.PrefixFrom(c.Interface.Addresses.V4, 32),
		},
		DNS:        []netip.Addr{v4DNS, v6DNS},
		MTU:        wgMTU,
		PublicKey:  peer.PublicKey,
		AllowedIPs: []netip.Prefix{v6AllowedIPs, v4AllowedIPs},
		Endpoint:   peer.Endpoint.Host,
		RoutingID:  [3]byte(c.ClientID),
	}, nil
}

func mustMarshal(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("impossible, failed to serialize a warp config to JSON: %v", err))
	}
	return raw
}
