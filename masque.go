package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/netip"
)

// masqueSNI is the TLS server name the official client uses for Zero Trust
// MASQUE tunnels; usque defaults to the consumer one.
const masqueSNI = "zt-masque.cloudflareclient.com"

// usqueConfig is the config.json of usque
// (https://github.com/Diniboy1123/usque), the de facto format for WARP
// MASQUE configs.
type usqueConfig struct {
	PrivateKey     string `json:"private_key"`
	EndpointV4     string `json:"endpoint_v4"`
	EndpointV6     string `json:"endpoint_v6"`
	EndpointH2V4   string `json:"endpoint_h2_v4"`
	EndpointH2V6   string `json:"endpoint_h2_v6"`
	EndpointPubKey string `json:"endpoint_pub_key"`
	ID             string `json:"id"`
	AccessToken    string `json:"access_token"`
	IPv4           string `json:"ipv4"`
	IPv6           string `json:"ipv6"`

	// Port is the preferred endpoint port; usque takes it as a flag.
	Port uint16 `json:"-"`
}

// toUsqueConfig converts a masque registration. The HTTP/2 endpoints are
// not part of the registration and are left empty for usque to default.
func (r *registrationResult) toUsqueConfig(privkey *ecdsa.PrivateKey) (*usqueConfig, error) {
	c := &r.Config
	if len(c.Peers) == 0 {
		return nil, fmt.Errorf("cloudflare returned a config with no peers")
	}
	peer := c.Peers[0]
	if block, _ := pem.Decode([]byte(peer.PublicKey)); block == nil {
		return nil, fmt.Errorf("peer public key is not a PEM block: %q", peer.PublicKey)
	}
	if len(peer.Endpoint.Ports) == 0 {
		return nil, fmt.Errorf("cloudflare returned an endpoint with no ports")
	}
	addrs := c.Interface.Addresses
	if !addrs.V4.Is4() || !addrs.V6.Is6() {
		return nil, fmt.Errorf("unexpected interface address families: v4=%s v6=%s", addrs.V4, addrs.V6)
	}
	endpointV4, err := netip.ParseAddrPort(peer.Endpoint.V4)
	if err != nil {
		return nil, fmt.Errorf("invalid v4 endpoint %q: %w", peer.Endpoint.V4, err)
	}
	endpointV6, err := netip.ParseAddrPort(peer.Endpoint.V6)
	if err != nil {
		return nil, fmt.Errorf("invalid v6 endpoint %q: %w", peer.Endpoint.V6, err)
	}
	der, err := x509.MarshalECPrivateKey(privkey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	return &usqueConfig{
		PrivateKey:     base64.StdEncoding.EncodeToString(der),
		EndpointV4:     endpointV4.Addr().String(),
		EndpointV6:     endpointV6.Addr().String(),
		EndpointPubKey: peer.PublicKey,
		ID:             r.ID,
		AccessToken:    r.Token,
		IPv4:           addrs.V4.String(),
		IPv6:           addrs.V6.String(),
		Port:           peer.Endpoint.Ports[0],
	}, nil
}
