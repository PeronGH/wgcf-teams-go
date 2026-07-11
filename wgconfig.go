package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
)

const wgTemplate = `# routing-id: 0x%s
[Interface]
PrivateKey = %s
Address = %s/32
Address = %s/128
DNS = 1.1.1.1
DNS = 2606:4700:4700::1111
MTU = 1420

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
Endpoint = %s
`

// wireGuardConfig holds the per-device values of a WARP WireGuard profile.
type wireGuardConfig struct {
	PrivateKey []byte
	PublicKey  []byte
	V4, V6     netip.Addr
	Endpoint   string
	RoutingID  [3]byte
}

func (c *wireGuardConfig) String() string {
	key := base64.StdEncoding.EncodeToString
	return fmt.Sprintf(wgTemplate,
		hex.EncodeToString(c.RoutingID[:]),
		key(c.PrivateKey), c.V4, c.V6,
		key(c.PublicKey), c.Endpoint)
}
