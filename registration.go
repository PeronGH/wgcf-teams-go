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

const (
	apiEndpoint   = "https://api.devices.cloudflare.com/v0/reg"
	userAgent     = "WARP for Linux"
	clientVersion = "linux-2026.7.1377.0"
)

// registration mirrors the payload of the official Linux client. The
// device identifiers are sent as explicit nulls, as that client does.
type registration struct {
	Type             string  `json:"type"`
	Key              string  `json:"key"`
	KeyType          string  `json:"key_type"`
	TunnelType       string  `json:"tunnel_type"`
	Tos              string  `json:"tos"`
	MultiUserEnabled bool    `json:"multi_user_enabled"`
	PhysicalDeviceID *string `json:"physical_device_id"`
	HardwareID       *string `json:"hardware_id"`
}

// response is the subset of the Cloudflare API response the tool uses.
// Result is null when the request fails.
type response struct {
	Result *registrationResult `json:"result"`
}

type registrationResult struct {
	ID      string `json:"id"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
	Token  string     `json:"token"`
	Config warpConfig `json:"config"`
}

type warpConfig struct {
	ClientID []byte `json:"client_id"`
	Peers    []struct {
		// Base64 of the raw key for wireguard, a PEM block for masque.
		PublicKey string `json:"public_key"`
		Endpoint  struct {
			Host  string   `json:"host"`
			V4    string   `json:"v4"`
			V6    string   `json:"v6"`
			Ports []uint16 `json:"ports"`
		} `json:"endpoint"`
	} `json:"peers"`
	Interface struct {
		Addresses struct {
			V4 netip.Addr `json:"v4"`
			V6 netip.Addr `json:"v6"`
		} `json:"addresses"`
	} `json:"interface"`
}

// register posts a device registration for the given base64 public key to
// the Cloudflare API.
func register(pubKey, keyType, tunnelType, token string) (*registrationResult, error) {
	reg := registration{
		Type:             "linux",
		Key:              pubKey,
		KeyType:          keyType,
		TunnelType:       tunnelType,
		Tos:              time.Now().UTC().Format(time.RFC3339),
		MultiUserEnabled: true,
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
	req.Header.Set("CF-Client-Version", clientVersion)
	req.Header.Set("User-Agent", userAgent)

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
	return envelope.Result, nil
}

func (r *registrationResult) toWGConfig(privkey *ecdh.PrivateKey) (*wireGuardConfig, error) {
	c := &r.Config
	if len(c.Peers) == 0 {
		return nil, fmt.Errorf("cloudflare returned a config with no peers")
	}
	peer := c.Peers[0]
	peerKey, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil || len(peerKey) != 32 {
		return nil, fmt.Errorf("peer public key is not a base64 32-byte key: %q", peer.PublicKey)
	}
	if len(c.ClientID) != 3 {
		return nil, fmt.Errorf("client id is not 3 bytes: %q", base64.StdEncoding.EncodeToString(c.ClientID))
	}
	addrs := c.Interface.Addresses
	if !addrs.V4.Is4() || !addrs.V6.Is6() {
		return nil, fmt.Errorf("unexpected interface address families: v4=%s v6=%s", addrs.V4, addrs.V6)
	}

	// The v4/v6 endpoints come with port 0; the candidate ports are listed
	// separately, preferred first.
	ports := peer.Endpoint.Ports
	if len(ports) == 0 {
		return nil, fmt.Errorf("cloudflare returned an endpoint with no ports")
	}
	port := ports[0]
	endpointV4, err := netip.ParseAddrPort(peer.Endpoint.V4)
	if err != nil {
		return nil, fmt.Errorf("invalid v4 endpoint %q: %w", peer.Endpoint.V4, err)
	}
	endpointV6, err := netip.ParseAddrPort(peer.Endpoint.V6)
	if err != nil {
		return nil, fmt.Errorf("invalid v6 endpoint %q: %w", peer.Endpoint.V6, err)
	}

	return &wireGuardConfig{
		PrivateKey:    privkey.Bytes(),
		OwnPublicKey:  privkey.PublicKey().Bytes(),
		V4:            addrs.V4,
		V6:            addrs.V6,
		DeviceID:      r.ID,
		AccountID:     r.Account.ID,
		Token:         r.Token,
		ClientID:      [3]byte(c.ClientID),
		PeerPublicKey: peerKey,
		EndpointV4:    netip.AddrPortFrom(endpointV4.Addr(), port),
		EndpointV6:    netip.AddrPortFrom(endpointV6.Addr(), port),
		EndpointHost:  peer.Endpoint.Host,
		AltPorts:      ports[1:],
	}, nil
}

func prettyJSON(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}
