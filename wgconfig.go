package main

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
)

// wireGuardConfig is a WireGuard profile in wg-quick(8) format.
type wireGuardConfig struct {
	PrivateKey  []byte
	IfAddresses []netip.Prefix
	DNS         []netip.Addr
	MTU         int
	PublicKey   []byte
	AllowedIPs  []netip.Prefix
	Endpoint    string
	RoutingID   [3]byte
}

func (c *wireGuardConfig) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "# routing-id: 0x%02x%02x%02x\n", c.RoutingID[0], c.RoutingID[1], c.RoutingID[2])

	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", base64.StdEncoding.EncodeToString(c.PrivateKey))
	for _, addr := range c.IfAddresses {
		fmt.Fprintf(&b, "Address = %s\n", addr)
	}
	for _, dns := range c.DNS {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	fmt.Fprintf(&b, "MTU = %d\n", c.MTU)

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", base64.StdEncoding.EncodeToString(c.PublicKey))
	for _, cidr := range c.AllowedIPs {
		fmt.Fprintf(&b, "AllowedIPs = %s\n", cidr)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", c.Endpoint)

	return b.String()
}
