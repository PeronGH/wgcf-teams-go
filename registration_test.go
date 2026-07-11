package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// A trimmed-down API response; extra fields exercise the lenient parsing.
const testResponse = `
{
  "result": {
    "id": "t.00000000-0000-0000-0000-000000000000",
    "version": "6.23",
    "config": {
      "client_id": "AQID",
      "peers": [
        {
          "public_key": "bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=",
          "endpoint": {
            "host": "engage.cloudflareclient.com:2408",
            "v4": "162.159.193.6:0",
            "v6": "[2606:4700:100::a29f:c106]:0"
          }
        }
      ],
      "interface": {
        "addresses": {
          "v4": "172.16.0.2",
          "v6": "2606:4700:110:8d80:5ee:f514:1b65:ecfe"
        }
      }
    }
  },
  "success": true,
  "errors": [],
  "messages": []
}
`

const expectedProfile = `# routing-id: 0x010203
[Interface]
PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
Address = 172.16.0.2/32
Address = 2606:4700:110:8d80:5ee:f514:1b65:ecfe/128
DNS = 1.1.1.1
DNS = 2606:4700:4700::1111
MTU = 1420

[Peer]
PublicKey = bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
Endpoint = engage.cloudflareclient.com:2408
`

func TestResponseToWGProfile(t *testing.T) {
	var envelope response
	if err := json.Unmarshal([]byte(testResponse), &envelope); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if envelope.Result == nil {
		t.Fatal("response has no result")
	}

	raw, err := base64.StdEncoding.DecodeString("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	if err != nil {
		t.Fatal(err)
	}
	privkey, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}

	wgConfig, err := envelope.Result.Config.toWGConfig(privkey)
	if err != nil {
		t.Fatalf("failed to convert to wireguard config: %v", err)
	}
	if got := wgConfig.String(); got != expectedProfile {
		t.Errorf("unexpected profile:\n%s\nwant:\n%s", got, expectedProfile)
	}
}
