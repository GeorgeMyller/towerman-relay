package relay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ConfigAPNs guarda as credenciais da chave .p8 do Apple Push Notification service.
type ConfigAPNs struct {
	KeyID    string
	TeamID   string
	Topic    string
	ChavePEM string
	Sandbox  bool
	Endpoint string // opcional para testes
}

// PedidoPush descreve um alerta de permissão pendente para acordar o iPhone/Apple Watch.
type PedidoPush struct {
	Token     string `json:"token"`
	Titulo    string `json:"title,omitempty"`
	Subtitulo string `json:"subtitle,omitempty"`
	Corpo     string `json:"body,omitempty"`
	Categoria string `json:"category,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	PromptID  string `json:"prompt_id,omitempty"`
}

// ClienteAPNs envia notificações HTTP/2 assinadas com ES256 (JWT) para a Apple.
type ClienteAPNs struct {
	cfg     ConfigAPNs
	chave   *ecdsa.PrivateKey
	httpCli *http.Client

	mu        sync.Mutex
	jwtToken  string
	jwtExpira time.Time
}

// NovoAPNsDeEnv inicializa o cliente APNs se as variáveis APNS_KEY_ID, APNS_TEAM_ID e APNS_KEY_P8 existirem.
func NovoAPNsDeEnv() (*ClienteAPNs, error) {
	keyID := strings.TrimSpace(os.Getenv("APNS_KEY_ID"))
	teamID := strings.TrimSpace(os.Getenv("APNS_TEAM_ID"))
	p8 := strings.TrimSpace(os.Getenv("APNS_KEY_P8"))
	if keyID == "" || teamID == "" || p8 == "" {
		return nil, nil
	}
	if !strings.Contains(p8, "BEGIN PRIVATE KEY") {
		if b, err := os.ReadFile(p8); err == nil {
			p8 = string(b)
		}
	}
	topic := strings.TrimSpace(os.Getenv("APNS_TOPIC"))
	if topic == "" {
		topic = "com.georgesouza.agentdeck"
	}
	return NovoAPNs(ConfigAPNs{
		KeyID:    keyID,
		TeamID:   teamID,
		Topic:    topic,
		ChavePEM: p8,
		Sandbox:  os.Getenv("APNS_SANDBOX") == "1" || os.Getenv("APNS_SANDBOX") == "sim",
	})
}

// NovoAPNs cria um cliente APNs validando a chave privada P-256 (.p8).
func NovoAPNs(cfg ConfigAPNs) (*ClienteAPNs, error) {
	bloco, _ := pem.Decode([]byte(cfg.ChavePEM))
	if bloco == nil {
		return nil, errors.New("chave .p8 PEM inválida")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(bloco.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ler chave .p8: %w", err)
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("chave .p8 não é ECDSA")
	}
	if cfg.Topic == "" {
		cfg.Topic = "com.georgesouza.agentdeck"
	}
	return &ClienteAPNs{
		cfg:     cfg,
		chave:   ecKey,
		httpCli: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Enviar dispara um Push APNs para acordar o iPhone/Apple Watch quando há um pedido à espera.
func (c *ClienteAPNs) Enviar(ctx context.Context, p PedidoPush) error {
	if c == nil || p.Token == "" {
		return nil
	}
	jwt, err := c.obterJWT(time.Now())
	if err != nil {
		return err
	}
	titulo := p.Titulo
	if titulo == "" {
		titulo = "Towerman"
	}
	corpo := p.Corpo
	if corpo == "" {
		corpo = "Um agente aguarda a sua permissão."
	}
	categoria := p.Categoria
	if categoria == "" {
		categoria = "prompt-allow|deny"
	}
	aps := map[string]any{
		"alert": map[string]string{
			"title":    titulo,
			"subtitle": p.Subtitulo,
			"body":     corpo,
		},
		"sound":              "default",
		"category":           categoria,
		"interruption-level": "time-sensitive",
		"content-available":  1,
	}
	payload := map[string]any{
		"aps":       aps,
		"agent_id":  p.AgentID,
		"prompt_id": p.PromptID,
	}
	dados, _ := json.Marshal(payload)

	base := c.cfg.Endpoint
	if base == "" {
		if c.cfg.Sandbox {
			base = "https://api.sandbox.push.apple.com"
		} else {
			base = "https://api.push.apple.com"
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+p.Token, bytes.NewReader(dados))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "bearer "+jwt)
	req.Header.Set("apns-topic", c.cfg.Topic)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	if p.AgentID != "" && p.PromptID != "" {
		req.Header.Set("apns-collapse-id", p.AgentID+"#"+p.PromptID)
	}
	resp, err := c.httpCli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("APNs devolveu %d", resp.StatusCode)
	}
	return nil
}

func (c *ClienteAPNs) obterJWT(agora time.Time) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jwtToken != "" && agora.Before(c.jwtExpira) {
		return c.jwtToken, nil
	}
	cab, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": c.cfg.KeyID})
	claims, _ := json.Marshal(map[string]any{"iss": c.cfg.TeamID, "iat": agora.Unix()})
	parte := base64.RawURLEncoding.EncodeToString(cab) + "." + base64.RawURLEncoding.EncodeToString(claims)
	hash := sha256.Sum256([]byte(parte))
	r, s, err := ecdsa.Sign(rand.Reader, c.chave, hash[:])
	if err != nil {
		return "", err
	}
	assinatura := make([]byte, 64)
	r.FillBytes(assinatura[:32])
	s.FillBytes(assinatura[32:])
	c.jwtToken = parte + "." + base64.RawURLEncoding.EncodeToString(assinatura)
	c.jwtExpira = agora.Add(50 * time.Minute)
	return c.jwtToken, nil
}

