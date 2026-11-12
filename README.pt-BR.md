# Towerman Relay

[English](README.md)

O relay opcional do [Towerman](https://github.com/GeorgeMyller/towerman). Ele permite que o app do iPhone chegue aos seus computadores fora de casa.

- **Cifra de ponta a ponta.** Cada aparelho pareado combina uma chave com o computador (X25519). Cada mensagem é selada com AES-256-GCM. O relay repassa envelopes que não consegue ler.
- **Só conexões de saída.** Os seus computadores se conectam ao relay. Você não abre portas em casa.
- **Privado por token.** O relay só aceita computadores que enviam um token de `TOWERMAN_RELAY_TOKENS`.
- **Pequeno.** Só a biblioteca padrão do Go, imagem distroless, roda numa instância gratuita do Render.

Não há relay público compartilhado. Cada pessoa roda o seu. Se você só precisa de acesso remoto para si, o [Tailscale](https://github.com/GeorgeMyller/towerman/blob/main/docs/pt-BR/acesso-remoto.md#opção-1-tailscale-recomendada) não precisa de servidor.

## Publicar

### Render (grátis)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/GeorgeMyller/towerman-relay)

1. Gere um token: `openssl rand -hex 32`.
2. Clique no botão, ou faça um fork deste repositório e crie um Blueprint a partir do `render.yaml`.
3. Defina `TOWERMAN_RELAY_TOKENS` com o seu token. Deixe os `APNS_*` vazios, a menos que configure push (abaixo).
4. Dê ao serviço um nome difícil de adivinhar.

O plano gratuito dorme sem uso. Um computador conectado o mantém acordado.

### Docker

```sh
docker build -t towerman-relay .
docker run -d --restart unless-stopped -p 8080:8080 \
  -e TOWERMAN_RELAY_TOKENS=<token> towerman-relay
```

O iOS exige HTTPS. Coloque um proxy reverso com TLS na frente (Caddy, nginx, Cloudflare), ou defina `TOWERMAN_RELAY_TLS_CERT` e `TOWERMAN_RELAY_TLS_KEY`.

### Pelo código

```sh
go install github.com/GeorgeMyller/towerman-relay/cmd/towerman-relay@latest
TOWERMAN_RELAY_TOKENS=<token> towerman-relay -addr :8080
```

Confira: `curl https://<seu-relay>/health` responde `{"ok":true,...}`.

## Conectar os computadores

Em cada computador com o Towerman, crie ou edite `~/.claude/towerman/config.json`:

```json
{
  "relay_url": "https://<seu-relay>",
  "relay_token": "<token>"
}
```

Reinicie o Towerman e pareie o iPhone de novo, na Wi-Fi de casa. Guia completo: [acesso remoto](https://github.com/GeorgeMyller/towerman/blob/main/docs/pt-BR/acesso-remoto.md).

## Configuração

| Variável | Efeito |
|---|---|
| `TOWERMAN_RELAY_TOKENS` | Tokens aceitos, separados por vírgula. **Sem ela, qualquer pessoa usa o relay** (o log avisa no arranque). |
| `PORT` | Porta (padrão `8080`). O `-addr` a sobrepõe. |
| `TOWERMAN_RELAY_TLS_CERT`, `TOWERMAN_RELAY_TLS_KEY` | Arquivos PEM para servir HTTPS diretamente. |
| `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_KEY_P8` | Chave APNs (texto P8 ou caminho). Opcional; exige conta Apple Developer paga. |
| `APNS_TOPIC` | O bundle ID do seu app iOS. Obrigatório quando a chave APNs está definida. |
| `APNS_SANDBOX=1` | Usa o sandbox do APNs (builds Debug). |

## Rotas

| Rota | Uso |
|---|---|
| `GET /health` | Verificação de saúde |
| `GET /s/{id}/ws?role=host` | Conexão do computador. Exige `X-Towerman-Relay-Token` e `X-Towerman-Host-Secret` |
| `GET /s/{id}/ws?role=viewer` | Conexão do iPhone (envelopes cifrados) |
| `POST /s/{id}/action` | Um pedido cifrado ao computador |

## Fonte do código

Este repositório é gerado a partir do código principal do Towerman. Abra issues e pull requests em [GeorgeMyller/towerman](https://github.com/GeorgeMyller/towerman).

## Licença

[MIT](LICENSE)
