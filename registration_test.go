package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// A trimmed-down copy of a real July 2026 API response with identifiers
// zeroed out; the extra fields exercise the lenient parsing.
const testResponse = `
{
  "result": {
    "id": "t.00000000-0000-0000-0000-000000000000",
    "physical_device_id": "00000000-0000-0000-0000-000000000000",
    "version": "6.23",
    "policy": {
      "policy_id": "default",
      "service_mode_v2": { "mode": "warp" },
      "tunnel_protocol": "masque",
      "post_quantum": "enabled_with_downgrades",
      "dns": { "doh_ips": ["162.159.36.1", "2606:4700:4700::1111"] }
    },
    "config": {
      "client_id": "AQID",
      "peers": [
        {
          "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
          "endpoint": {
            "v4": "162.159.193.6:0",
            "v6": "[2606:4700:100::a29f:c106]:0",
            "host": "engage.cloudflareclient.com:2408",
            "ports": [2408, 500, 1701, 4500]
          }
        }
      ],
      "services": { "http_proxy": "172.16.0.1:2480" },
      "interface": {
        "addresses": {
          "v4": "100.96.0.3",
          "v6": "2606:4700:cf1:1000::3"
        }
      },
      "metrics": { "ping": 900, "report": 900 }
    },
    "dex_tests": [
      {
        "test_id": "00000000-0000-0000-0000-000000000000",
        "name": "Cloudflare Status",
        "data": { "host": "https://www.cloudflarestatus.com/", "kind": "http" }
      }
    ]
  },
  "success": true,
  "errors": [],
  "messages": []
}
`

const expectedProfile = `# routing-id: 0x010203
[Interface]
PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
Address = 100.96.0.3/32
Address = 2606:4700:cf1:1000::3/128
DNS = 1.1.1.1
DNS = 2606:4700:4700::1111
MTU = 1420

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
Endpoint = engage.cloudflareclient.com:2408
# alternative endpoint ports: 500, 1701, 4500
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

func TestAltEndpointPorts(t *testing.T) {
	cases := []struct {
		name  string
		host  string
		ports []int
		want  []int
	}{
		{"excludes active port", "engage.cloudflareclient.com:2408", []int{2408, 500}, []int{500}},
		{"host without port keeps all", "engage.cloudflareclient.com", []int{2408, 500}, []int{2408, 500}},
		{"no ports advertised", "engage.cloudflareclient.com:2408", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := altEndpointPorts(c.host, c.ports)
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}
