package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Fixture and expectations ported from upstream:
// https://github.com/poscat0x04/wgcf-teams/blob/master/src/registration.rs
const testResponse = `
{
  "result" : {
    "id" : "t.a849f2f4-61dd-11ed-8b7d-3acbb31d7d51",
    "version" : "6.16",
    "updated" : "2022-11-11T16:26:56.002100164Z",
    "type" : "i",
    "key" : "/V3c9pAqcqy6SpZRq9bck69mmfFzsTi7mG8TFXW/NwU=",
    "policy" : {
      "app_url" : "https://poscat.cloudflareaccess.com",
      "captive_portal" : 180,
      "allowed_to_leave" : true,
      "switch_locked" : false,
      "fallback_domains" : [
        { "suffix" : "home.arpa" },
        { "suffix" : "local" }
      ],
      "service_mode_v2" : { "mode" : "warp" },
      "allow_updates" : false,
      "support_url" : "",
      "exclude" : [
        { "address" : "10.0.0.0/8" },
        { "host" : "bilibili.com" }
      ],
      "gateway_unique_id" : "07248f8927685cade2b3b4eb853a8c57",
      "allow_mode_switch" : true,
      "auto_connect" : 0,
      "disable_auto_fallback" : false,
      "organization" : "poscat"
    },
    "token" : "21b87a20-cd76-4305-a5f0-0bf40b8fdc51",
    "locale" : "en-US",
    "config" : {
      "client_id" : "9agP",
      "peers" : [
        {
          "public_key" : "bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=",
          "endpoint" : {
            "host" : "engage.cloudflareclient.com:2408",
            "v4" : "162.159.193.6:0",
            "v6" : "[2606:4700:100::a29f:c106]:0"
          }
        }
      ],
      "services" : { "http_proxy" : "172.16.0.1:2480" },
      "interface" : {
        "addresses" : {
          "v4" : "172.16.0.2",
          "v6" : "2606:4700:110:8d80:5ee:f514:1b65:ecfe"
        }
      },
      "metrics" : { "report" : 900, "ping" : 900 }
    },
    "created" : "2022-11-11T16:26:56.002100164Z",
    "override_codes" : {
      "disable_for_time" : {
        "seconds" : 86400,
        "secret" : "dfad7ec220d2e0187781d41229114081"
      }
    },
    "account" : {
      "managed" : "not_api_managed",
      "id" : "07248f8927685cace2beb4eb853a8c57",
      "organization" : "poscat",
      "account_type" : "team"
    },
    "install_id" : "",
    "name" : "",
    "model" : "iPad13,8"
  },
  "success" : true,
  "errors" : [],
  "messages" : []
}
`

const expectedProfile = `
# routing-id: 0xf5a80f
[Interface]
PrivateKey = iHtAU4H3BRyVqrw3dNd9Exwh4eZvsiOgw0Gqb0oHB3U=
Address = 2606:4700:110:8d80:5ee:f514:1b65:ecfe/128
Address = 172.16.0.2/32
DNS = 1.1.1.1
DNS = 2606:4700:4700::1111
MTU = 1420

[Peer]
PublicKey = bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = ::/0
AllowedIPs = 0.0.0.0/0
Endpoint = engage.cloudflareclient.com:2408
`

func mustParseResponse(t *testing.T) *registrationResult {
	t.Helper()
	var envelope cfResp[registrationResult]
	if err := json.Unmarshal([]byte(testResponse), &envelope); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	result, err := envelope.getResult()
	if err != nil {
		t.Fatalf("response has no result: %v", err)
	}
	return result
}

func TestResponseParsing(t *testing.T) {
	result := mustParseResponse(t)
	if got := result.Config.Interface.Addresses.V4.String(); got != "172.16.0.2" {
		t.Errorf("unexpected v4 interface address: %s", got)
	}
	if got := len(result.Config.ClientID); got != 3 {
		t.Errorf("unexpected client id length: %d", got)
	}
}

func TestWGProfileConversion(t *testing.T) {
	result := mustParseResponse(t)

	raw, err := base64.StdEncoding.DecodeString("iHtAU4H3BRyVqrw3dNd9Exwh4eZvsiOgw0Gqb0oHB3U=")
	if err != nil {
		t.Fatal(err)
	}
	privkey, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}

	wgConfig, err := result.Config.toWGConfig(privkey)
	if err != nil {
		t.Fatalf("failed to convert to wireguard config: %v", err)
	}
	if got, want := strings.TrimSpace(wgConfig.String()), strings.TrimSpace(expectedProfile); got != want {
		t.Errorf("unexpected profile:\n%s\nwant:\n%s", got, want)
	}
}
