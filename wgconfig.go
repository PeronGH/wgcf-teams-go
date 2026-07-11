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
	License       string
	Token         string
	ClientID      [3]byte
	PeerPublicKey []byte
	EndpointV4    netip.AddrPort
	EndpointV6    netip.AddrPort
	EndpointHost  string
	AltPorts      []int
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

	b.WriteString("\n# Cloudflare Warp specific variables\n")
	fmt.Fprintf(&b, "#CFDeviceId = %s\n", c.DeviceID)
	fmt.Fprintf(&b, "#CFAccountId = %s\n", c.AccountID)
	fmt.Fprintf(&b, "#CFAccountLicense = %s\n", c.License)
	fmt.Fprintf(&b, "#CFToken = %s\n", c.Token)
	b.WriteString("## Cloudflare Client ID in various formats.\n")
	b.WriteString("## NOTE: this is also referred to as \"reserved key\" as the client ID\n")
	b.WriteString("##       is put in the reserved field in the WireGuard header.\n")
	fmt.Fprintf(&b, "#CFClientIdB64 = %s\n", key(c.ClientID[:]))
	fmt.Fprintf(&b, "#CFClientIdHex = 0x%s\n", hex.EncodeToString(c.ClientID[:]))
	fmt.Fprintf(&b, "#CFClientIdDec = [%d, %d, %d]\n", c.ClientID[0], c.ClientID[1], c.ClientID[2])

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", key(c.PeerPublicKey))
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	b.WriteString("PersistentKeepalive = 25\n")
	if len(c.AltPorts) > 0 {
		fmt.Fprintf(&b, "# If UDP %d is blocked, you could try %s.\n", c.EndpointV4.Port(), udpOrList(c.AltPorts))
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", c.EndpointV4)
	fmt.Fprintf(&b, "#Endpoint = %s\n", c.EndpointV6)
	fmt.Fprintf(&b, "#Endpoint = %s\n", c.EndpointHost)

	return b.String()
}

// udpOrList renders ports as a prose list: "UDP 500, UDP 1701, or UDP 4500".
func udpOrList(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = "UDP " + strconv.Itoa(p)
	}
	switch len(parts) {
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " or " + parts[1]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + ", or " + parts[len(parts)-1]
	}
}
