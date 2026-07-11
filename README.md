# wgcf-teams-go

Extract WireGuard configurations from Cloudflare's WARP for Teams.

A dependency-free Go port of [poscat0x04/wgcf-teams](https://github.com/poscat0x04/wgcf-teams).

## Installing

```
go install github.com/PeronGH/wgcf-teams-go@latest
```

## Usage

```
wgcf-teams-go [-p] > wg.conf
```

The program asks for the JWT token of your organization on stderr; see
[guide.md](guide.md) for where to find it after logging in to
`https://<your-org>.cloudflareaccess.com/warp`. The WireGuard profile is
printed to stdout.

Pass `-p` / `--prompt` to supply your own WireGuard private key instead of
generating one.
