# Towerman Relay

[Português (Brasil)](README.pt-BR.md)

The optional relay for [Towerman](https://github.com/GeorgeMyller/towerman). It lets the Towerman iPhone app reach your computers away from home.

- **End-to-end encrypted.** Each paired device agrees on a key with the computer (X25519). Every message is sealed with AES-256-GCM. The relay forwards envelopes it cannot read.
- **Outbound only.** Your computers connect to the relay. You open no ports at home.
- **Private by token.** The relay only accepts computers that send a token from `TOWERMAN_RELAY_TOKENS`.
- **Small.** Go standard library only, a distroless image, runs on a free Render instance.

There is no shared public relay. Each person runs their own. If you only need remote access for yourself, [Tailscale](https://github.com/GeorgeMyller/towerman/blob/main/docs/en/remote-access.md#option-1-tailscale-recommended) needs no server at all.

## Deploy

### Render (free)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/GeorgeMyller/towerman-relay)

1. Create a token: `openssl rand -hex 32`.
2. Click the button, or fork this repository and create a Blueprint from `render.yaml`.
3. Set `TOWERMAN_RELAY_TOKENS` to your token. Leave the `APNS_*` values empty unless you set up push (below).
4. Give the service a name that is not easy to guess.

The free plan sleeps when idle. A connected computer keeps it awake.

### Docker

```sh
docker build -t towerman-relay .
docker run -d --restart unless-stopped -p 8080:8080 \
  -e TOWERMAN_RELAY_TOKENS=<token> towerman-relay
```

iOS needs HTTPS. Put a reverse proxy with TLS in front (Caddy, nginx, Cloudflare), or set `TOWERMAN_RELAY_TLS_CERT` and `TOWERMAN_RELAY_TLS_KEY`.

### From source

```sh
go install github.com/GeorgeMyller/towerman-relay/cmd/towerman-relay@latest
TOWERMAN_RELAY_TOKENS=<token> towerman-relay -addr :8080
```

Check it: `curl https://<your-relay>/health` answers `{"ok":true,...}`.

## Connect your computers

On each computer running Towerman, create or edit `~/.claude/towerman/config.json`:

```json
{
  "relay_url": "https://<your-relay>",
  "relay_token": "<token>"
}
```

Restart Towerman, then pair the iPhone again on your home Wi-Fi. Full guide: [remote access](https://github.com/GeorgeMyller/towerman/blob/main/docs/en/remote-access.md).

## Configuration

| Variable | Effect |
|---|---|
| `TOWERMAN_RELAY_TOKENS` | Accepted tokens, comma-separated. **Without it, anyone can use the relay** (the log warns at startup). |
| `PORT` | Listen port (default `8080`). `-addr` overrides it. |
| `TOWERMAN_RELAY_TLS_CERT`, `TOWERMAN_RELAY_TLS_KEY` | PEM files to serve HTTPS directly. |
| `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_KEY_P8` | APNs key (P8 text or file path). Optional; needs a paid Apple Developer account. |
| `APNS_TOPIC` | Your iOS bundle ID. Required when the APNs key is set. |
| `APNS_SANDBOX=1` | Use the APNs sandbox (Debug builds). |

## Endpoints

| Route | Use |
|---|---|
| `GET /health` | Health check |
| `GET /s/{id}/ws?role=host` | Computer connection. Needs `X-Towerman-Relay-Token` and `X-Towerman-Host-Secret` |
| `GET /s/{id}/ws?role=viewer` | iPhone connection (encrypted envelopes) |
| `POST /s/{id}/action` | One encrypted request to the computer |

## Source of truth

This repository is generated from the main Towerman code. Open issues and pull requests in [GeorgeMyller/towerman](https://github.com/GeorgeMyller/towerman).

## License

[MIT](LICENSE)
