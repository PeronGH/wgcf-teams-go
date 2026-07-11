# wgcf-teams-go

Generate WireGuard configurations for Cloudflare WARP for Teams (Zero Trust).

## Install

```
go install github.com/PeronGH/wgcf-teams-go@latest
```

## Usage

```
wgcf-teams-go > wg.conf
```

The tool registers a new device with your Zero Trust organization and prints a
wg-quick(8) profile to stdout; prompts go to stderr. Pass `-p` / `--prompt` to
supply your own WireGuard private key instead of generating one.

## Obtaining the JWT token

1. Open `https://<your-team>.cloudflareaccess.com/warp` in a browser and
   complete the login.
2. On the page shown after login, open the developer tools and inspect the
   `<head>` element. It contains a `<meta>` tag with a very long URL ending in
   `?token=eyJ...`.
3. Copy everything after `?token=` and paste it into the tool's prompt.
