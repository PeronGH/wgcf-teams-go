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
After you log in, the success page holds the enrollment token. Open the
browser console (F12) and run:

```js
copy(document.getElementById('redirect-button').getAttribute('onclick'))
```

That copies the login callback to the clipboard via the console's `copy()`
helper. Paste it into the prompt — the token is extracted automatically
(pasting the `com.cloudflare.warp://...?token=...` URL or the bare token works
too). The tool then registers a new device and prints a wg-quick(8) profile to
stdout. Comments in the profile carry everything else worth keeping: your
public key, the device/account ids and device API token, the client id (the
value warp writes into the wireguard reserved header bytes) in three
encodings, and alternative endpoints and ports advertised by Cloudflare.

The token expires 60 seconds after login — paste it promptly. If registration
fails with an expiry error, refresh the success page and copy a fresh one.

Pass `-p` / `--prompt` to supply your own WireGuard private key instead of
generating one.

> An automatic, paste-free flow is not possible: Cloudflare delivers the token
> only through the fixed `com.cloudflare.warp://` custom URL scheme, which the
> browser hands to the OS-registered protocol handler (the official WARP
> client), never to a local HTTP callback.
