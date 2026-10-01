package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// The MASQUE config of a real consumer registration.
const testMASQUEResponse = `
{
  "result": {
    "id": "00000000-0000-0000-0000-000000000000",
    "token": "00000000-0000-0000-0000-000000000000",
    "key_type": "secp256r1",
    "tunnel_type": "masque",
    "config": {
      "client_id": "e4/K",
      "peers": [{
        "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG\n7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==\n-----END PUBLIC KEY-----\n",
        "endpoint": {
          "v4": "162.159.198.2:0",
          "v6": "[2606:4700:103::2]:0",
          "host": "engage.cloudflareclient.com:2408",
          "ports": [443, 500, 1701, 4500, 4443, 8443, 8095]
        }
      }],
      "interface": {
        "addresses": { "v4": "172.16.0.2", "v6": "2606:4700:110:824f:500:7deb:1761:fd9e" }
      }
    }
  },
  "success": true,
  "errors": [],
  "messages": []
}
`

func TestResponseToUsqueConfig(t *testing.T) {
	var envelope response
	if err := json.Unmarshal([]byte(testMASQUEResponse), &envelope); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	c, err := envelope.Result.toUsqueConfig(privkey)
	if err != nil {
		t.Fatalf("failed to convert to usque config: %v", err)
	}

	der, err := base64.StdEncoding.DecodeString(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseECPrivateKey(der)
	if err != nil || !parsed.Equal(privkey) {
		t.Fatalf("private key does not round-trip: %v", err)
	}

	c.PrivateKey = ""
	want := usqueConfig{
		EndpointV4:     "162.159.198.2",
		EndpointV6:     "2606:4700:103::2",
		EndpointPubKey: envelope.Result.Config.Peers[0].PublicKey,
		ID:             "00000000-0000-0000-0000-000000000000",
		AccessToken:    "00000000-0000-0000-0000-000000000000",
		IPv4:           "172.16.0.2",
		IPv6:           "2606:4700:110:824f:500:7deb:1761:fd9e",
		Port:           443,
	}
	if *c != want {
		t.Errorf("unexpected config:\n%+v\nwant:\n%+v", *c, want)
	}
}
