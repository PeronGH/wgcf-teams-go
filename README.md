# wgcf-teams-go

Generate WireGuard configurations for Cloudflare WARP for Teams (Zero Trust).

## Install

```
go install github.com/PeronGH/wgcf-teams-go@latest
```

## Usage

```
wgcf-teams-go <team-name> > wg.conf
```

The tool opens `https://<team-name>.cloudflareaccess.com/warp` in your browser.
After you log in, the success page tries to launch the WARP client via a
`com.cloudflare.warp://` link — decline that, view the page source instead, and
copy the `com.cloudflare.warp://...?token=...` URL from the `<meta>` tag in
`<head>`. Paste the URL (or just the token) into the prompt; the tool registers
a new device and prints a wg-quick(8) profile to stdout.

The token expires quickly — paste it promptly. If registration fails, refresh
the success page and copy a fresh one.

Pass `-p` / `--prompt` to supply your own WireGuard private key instead of
generating one.

> An automatic, paste-free flow is not possible: Cloudflare delivers the token
> only through the fixed `com.cloudflare.warp://` custom URL scheme, which the
> browser hands to the OS-registered protocol handler (the official WARP
> client), never to a local HTTP callback.
