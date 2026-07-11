package main

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
)

func TestWGProfileGeneration(t *testing.T) {
	privkey, err := base64.StdEncoding.DecodeString("iHtAU4H3BRyVqrw3dNd9Exwh4eZvsiOgw0Gqb0oHB3U=")
	if err != nil {
		t.Fatal(err)
	}
	pubkey, err := base64.StdEncoding.DecodeString("bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=")
	if err != nil {
		t.Fatal(err)
	}

	expected := `
# routing-id: 0x010203
[Interface]
PrivateKey = iHtAU4H3BRyVqrw3dNd9Exwh4eZvsiOgw0Gqb0oHB3U=
Address = 172.0.0.1/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = ::/0
AllowedIPs = 0.0.0.0/0
Endpoint = engage.cloudflareclient.com
`

	cfg := &wireGuardConfig{
		PrivateKey:  privkey,
		IfAddresses: []netip.Prefix{netip.MustParsePrefix("172.0.0.1/32")},
		DNS:         []netip.Addr{v4DNS},
		MTU:         wgMTU,
		PublicKey:   pubkey,
		AllowedIPs:  []netip.Prefix{v6AllowedIPs, v4AllowedIPs},
		Endpoint:    "engage.cloudflareclient.com",
		RoutingID:   [3]byte{1, 2, 3},
	}

	if got, want := strings.TrimSpace(cfg.String()), strings.TrimSpace(expected); got != want {
		t.Errorf("unexpected profile:\n%s\nwant:\n%s", got, want)
	}
}
