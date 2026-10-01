package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// wireGuardConfig holds everything from a device registration that goes into
// the emitted profile, either as settings or as informational comments.
type wireGuardConfig struct {
	PrivateKey    []byte
	OwnPublicKey  []byte
	V4, V6        netip.Addr
	DeviceID      string
	AccountID     string
	Token         string
	ClientID      [3]byte
	PeerPublicKey []byte
	EndpointV4    netip.AddrPort
	EndpointV6    netip.AddrPort
	EndpointHost  string
	AltPorts      []uint16
}

func (c *wireGuardConfig) String() string {
	key := base64.StdEncoding.EncodeToString
	var b strings.Builder

	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", key(c.PrivateKey))
	fmt.Fprintf(&b, "#PublicKey = %s\n", key(c.OwnPublicKey))
	fmt.Fprintf(&b, "Address = %s, %s\n", c.V4, c.V6)
	b.WriteString("DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001\n")
	b.WriteString("MTU = 1280\n")

	b.WriteString("\n# Cloudflare device metadata; the client id is what warp writes into\n")
	b.WriteString("# the reserved bytes of the wireguard message header.\n")
	fmt.Fprintf(&b, "#DeviceId = %s\n", c.DeviceID)
	fmt.Fprintf(&b, "#AccountId = %s\n", c.AccountID)
	fmt.Fprintf(&b, "#ApiToken = %s\n", c.Token)
	id := c.ClientID
	fmt.Fprintf(&b, "#ClientId = %s (hex 0x%s, decimal [%d, %d, %d])\n",
		key(id[:]), hex.EncodeToString(id[:]), id[0], id[1], id[2])

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", key(c.PeerPublicKey))
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	b.WriteString("PersistentKeepalive = 25\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", c.EndpointV4)
	fmt.Fprintf(&b, "#Endpoint = %s\n", c.EndpointV6)
	if c.EndpointHost != "" {
		fmt.Fprintf(&b, "#Endpoint = %s\n", c.EndpointHost)
	}
	if len(c.AltPorts) > 0 {
		ports := make([]string, len(c.AltPorts))
		for i, p := range c.AltPorts {
			ports[i] = strconv.Itoa(int(p))
		}
		fmt.Fprintf(&b, "# the endpoint also listens on UDP %s\n", strings.Join(ports, ", "))
	}

	return b.String()
}
