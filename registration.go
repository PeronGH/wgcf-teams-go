package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const apiEndpoint = "https://zero-trust-client.cloudflareclient.com/v0i2308311933/reg"

type registration struct {
	Key         string `json:"key"`
	Tos         string `json:"tos"`
	Model       string `json:"model"`
	FCMToken    string `json:"fcm_token"`
	DeviceToken string `json:"device_token"`
}

// response is the subset of the Cloudflare API response the tool uses.
// Result is null when the request fails.
type response struct {
	Result *registrationResult `json:"result"`
}

type registrationResult struct {
	ID      string `json:"id"`
	Account struct {
		ID      string `json:"id"`
		License string `json:"license"`
	} `json:"account"`
	Token  string     `json:"token"`
	Config warpConfig `json:"config"`
}

type warpConfig struct {
	ClientID []byte `json:"client_id"`
	Peers    []struct {
		PublicKey []byte `json:"public_key"`
		Endpoint  struct {
			Host  string `json:"host"`
			V4    string `json:"v4"`
			V6    string `json:"v6"`
			Ports []int  `json:"ports"`
		} `json:"endpoint"`
	} `json:"peers"`
	Interface struct {
		Addresses struct {
			V4 netip.Addr `json:"v4"`
			V6 netip.Addr `json:"v6"`
		} `json:"addresses"`
	} `json:"interface"`
}

// register posts a device registration to the Cloudflare API and converts the
// response into a WireGuard config.
func register(privkey *ecdh.PrivateKey, token string) (*wireGuardConfig, error) {
	reg := registration{
		Key:   base64.StdEncoding.EncodeToString(privkey.PublicKey().Bytes()),
		Tos:   time.Now().Format(time.RFC3339Nano),
		Model: "iPad13,8",
	}
	body, err := json.Marshal(reg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize registration: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
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
	var envelope response
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("unexpected response from cloudflare (HTTP %s): %.200s", resp.Status, raw)
	}
	if envelope.Result == nil {
		return nil, fmt.Errorf("cloudflare API request failed (HTTP %s):\n%s", resp.Status, prettyJSON(raw))
	}
	return envelope.Result.toWGConfig(privkey)
}

func (r *registrationResult) toWGConfig(privkey *ecdh.PrivateKey) (*wireGuardConfig, error) {
	c := &r.Config
	if len(c.Peers) == 0 {
		return nil, fmt.Errorf("cloudflare returned a config with no peers")
	}
	peer := c.Peers[0]
	if len(peer.PublicKey) != 32 {
		return nil, fmt.Errorf("peer public key is not 32 bytes: %q", base64.StdEncoding.EncodeToString(peer.PublicKey))
	}
	if len(c.ClientID) != 3 {
		return nil, fmt.Errorf("client id is not 3 bytes: %q", base64.StdEncoding.EncodeToString(c.ClientID))
	}
	addrs := c.Interface.Addresses
	if !addrs.V4.Is4() || !addrs.V6.Is6() {
		return nil, fmt.Errorf("unexpected interface address families: v4=%s v6=%s", addrs.V4, addrs.V6)
	}

	// The v4/v6 endpoints come with port 0; the real port is in the host.
	_, portStr, err := net.SplitHostPort(peer.Endpoint.Host)
	if err != nil {
		return nil, fmt.Errorf("endpoint host %q has no port: %w", peer.Endpoint.Host, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("endpoint host %q has an invalid port: %w", peer.Endpoint.Host, err)
	}
	endpointV4, err := netip.ParseAddrPort(peer.Endpoint.V4)
	if err != nil {
		return nil, fmt.Errorf("invalid v4 endpoint %q: %w", peer.Endpoint.V4, err)
	}
	endpointV6, err := netip.ParseAddrPort(peer.Endpoint.V6)
	if err != nil {
		return nil, fmt.Errorf("invalid v6 endpoint %q: %w", peer.Endpoint.V6, err)
	}

	license := r.Account.License
	if license == "" {
		license = "N/A"
	}

	return &wireGuardConfig{
		PrivateKey:    privkey.Bytes(),
		OwnPublicKey:  privkey.PublicKey().Bytes(),
		V4:            addrs.V4,
		V6:            addrs.V6,
		DeviceID:      r.ID,
		AccountID:     r.Account.ID,
		License:       license,
		Token:         r.Token,
		ClientID:      [3]byte(c.ClientID),
		PeerPublicKey: peer.PublicKey,
		EndpointV4:    netip.AddrPortFrom(endpointV4.Addr(), uint16(port)),
		EndpointV6:    netip.AddrPortFrom(endpointV6.Addr(), uint16(port)),
		EndpointHost:  peer.Endpoint.Host,
		AltPorts:      altEndpointPorts(peer.Endpoint.Host, peer.Endpoint.Ports),
	}, nil
}

// altEndpointPorts returns the advertised endpoint ports, excluding the one
// already used by the endpoint host.
func altEndpointPorts(host string, ports []int) []int {
	_, current, err := net.SplitHostPort(host)
	if err != nil {
		current = ""
	}
	var alt []int
	for _, p := range ports {
		if strconv.Itoa(p) != current {
			alt = append(alt, p)
		}
	}
	return alt
}

func prettyJSON(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}
