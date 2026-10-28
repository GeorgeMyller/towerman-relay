package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"
)

//go:embed landing.html
var paginaLanding []byte

var reIDValido = regexp.MustCompile(`^[A-Za-z0-9_-]{4,64}$`)

// Mensagem trafega entre o Mac, o Relay e os aparelhos pareados.
// O campo Payload é sempre cifrado ponta a ponta (AES-256-GCM) entre o Mac e o aparelho.
type Mensagem struct {
	Tipo    string       `json:"type"`              // viewers | state | action | action_reply | push_wake
	Device  string       `json:"device,omitempty"`  // id do aparelho destinatário ou remetente
	ReqID   string       `json:"req_id,omitempty"`  // correlação de ação (action -> action_reply)
	Count   int          `json:"count,omitempty"`   // número de aparelhos com ecrã aberto na sala
	Devices []string     `json:"devices,omitempty"` // ids dos aparelhos ligados agora
	Payload string       `json:"payload,omitempty"` // base64url(nonce || ciphertext || tag)
	Status  int          `json:"status,omitempty"`  // código HTTP da ação executada
	Pushes  []PedidoPush `json:"pushes,omitempty"`  // alertas APNs para acordar aparelhos em segundo plano
}

type sala struct {
	mu           sync.Mutex
	id           string
	segredoHash  [32]byte
	temSegredo   bool
	host         *ConnWS
	viewers      map[string]*ConnWS
	pendentesHTTP map[string]chan Mensagem
}

// Servidor é o Relay WebSocket Zero-Knowledge em memória.
type Servidor struct {
	apns  *ClienteAPNs
	mu    sync.Mutex
	salas map[string]*sala
}

// NovoServidor cria uma instância do Relay WebSocket.
func NovoServidor(apns *ClienteAPNs) *Servidor {
	return &Servidor{
		apns:  apns,
		salas: make(map[string]*sala),
	}
}

// Handler devolve as rotas HTTP/WebSocket do Relay e a landing page em GET /.
func (s *Servidor) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(paginaLanding)
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"service":"towerman-relay"}`))
	})
	mux.HandleFunc("GET /s/{id}/health", s.healthSala)
	mux.HandleFunc("GET /s/{id}/ws", s.ligarWS)
	mux.HandleFunc("POST /s/{id}/action", s.acaoHTTP)
	return mux
}

func (s *Servidor) obterSala(id string) *sala {
	s.mu.Lock()
	defer s.mu.Unlock()
	sl, ok := s.salas[id]
	if !ok {
		sl = &sala{
			id:            id,
			viewers:       make(map[string]*ConnWS),
			pendentesHTTP: make(map[string]chan Mensagem),
		}
		s.salas[id] = sl
	}
	return sl
}

// healthSala responde 200 OK apenas quando o Mac dono da sala está ligado ao Relay.
// Assim, o ServerLink.probe do iPhone reconhece a identidade da máquina fora de casa.
func (s *Servidor) healthSala(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !reIDValido.MatchString(id) {
		http.Error(w, `{"error":"id inválido"}`, http.StatusBadRequest)
		return
	}
	sl := s.obterSala(id)
	sl.mu.Lock()
	online := sl.host != nil
	sl.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !online {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "id": id})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": id})
}

func (s *Servidor) ligarWS(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !reIDValido.MatchString(id) {
		http.Error(w, `{"error":"id inválido"}`, http.StatusBadRequest)
		return
	}
	papel := r.URL.Query().Get("role")
	switch papel {
	case "host":
		s.servirHost(w, r, id)
	case "viewer":
		s.servirViewer(w, r, id)
	default:
		http.Error(w, `{"error":"role deve ser host ou viewer"}`, http.StatusBadRequest)
	}
}

func (s *Servidor) servirHost(w http.ResponseWriter, r *http.Request, id string) {
	segredo := r.Header.Get("X-Towerman-Host-Secret")
	if len(segredo) < 16 {
		http.Error(w, `{"error":"X-Towerman-Host-Secret obrigatório"}`, http.StatusUnauthorized)
		return
	}
	hash := sha256.Sum256([]byte(segredo))
	sl := s.obterSala(id)

	sl.mu.Lock()
	if sl.temSegredo && subtle.ConstantTimeCompare(sl.segredoHash[:], hash[:]) != 1 {
		sl.mu.Unlock()
		http.Error(w, `{"error":"segredo do servidor incorreto"}`, http.StatusForbidden)
		return
	}
	sl.segredoHash = hash
	sl.temSegredo = true
	sl.mu.Unlock()

	ws, err := AceitarWS(w, r)
	if err != nil {
		return
	}

	sl.mu.Lock()
	antigo := sl.host
	sl.host = ws
	notificar := sl.mensagemViewersSemLock()
	sl.mu.Unlock()

	if antigo != nil {
		_ = antigo.Fechar()
	}
	_ = ws.EscreverJSON(notificar)

	defer func() {
		sl.mu.Lock()
		if sl.host == ws {
			sl.host = nil
		}
		sl.mu.Unlock()
		_ = ws.Fechar()
	}()

	ping := time.NewTicker(45 * time.Second)
	defer ping.Stop()
	go func() {
		for range ping.C {
			if ws.Ping() != nil {
				return
			}
		}
	}()

	for {
		var msg Mensagem
		if err := ws.LerJSON(&msg); err != nil {
			return
		}
		switch msg.Tipo {
		case "state":
			sl.mu.Lock()
			if msg.Device != "" {
				if v, ok := sl.viewers[msg.Device]; ok {
					_ = v.EscreverJSON(msg)
				}
			} else {
				for _, v := range sl.viewers {
					_ = v.EscreverJSON(msg)
				}
			}
			sl.mu.Unlock()

		case "action_reply":
			sl.mu.Lock()
			if ch, ok := sl.pendentesHTTP[msg.ReqID]; ok {
				select {
				case ch <- msg:
				default:
				}
			} else if msg.Device != "" {
				if v, ok := sl.viewers[msg.Device]; ok {
					_ = v.EscreverJSON(msg)
				}
			}
			sl.mu.Unlock()

		case "push_wake":
			if s.apns != nil {
				for _, p := range msg.Pushes {
					go func(pedido PedidoPush) {
						ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
						defer cancel()
						if err := s.apns.Enviar(ctx, pedido); err != nil {
							log.Printf("relay: erro APNs: %v", err)
						}
					}(p)
				}
			}
		}
	}
}

func (s *Servidor) servirViewer(w http.ResponseWriter, r *http.Request, id string) {
	deviceID := r.URL.Query().Get("device")
	if !reIDValido.MatchString(deviceID) {
		http.Error(w, `{"error":"device inválido"}`, http.StatusBadRequest)
		return
	}
	ws, err := AceitarWS(w, r)
	if err != nil {
		return
	}
	sl := s.obterSala(id)

	sl.mu.Lock()
	if antigo, ok := sl.viewers[deviceID]; ok {
		_ = antigo.Fechar()
	}
	sl.viewers[deviceID] = ws
	host := sl.host
	aviso := sl.mensagemViewersSemLock()
	sl.mu.Unlock()

	if host != nil {
		_ = host.EscreverJSON(aviso)
	}

	defer func() {
		sl.mu.Lock()
		if sl.viewers[deviceID] == ws {
			delete(sl.viewers, deviceID)
		}
		h := sl.host
		avisoSaida := sl.mensagemViewersSemLock()
		sl.mu.Unlock()
		if h != nil {
			_ = h.EscreverJSON(avisoSaida)
		}
		_ = ws.Fechar()
	}()

	for {
		var msg Mensagem
		if err := ws.LerJSON(&msg); err != nil {
			return
		}
		if msg.Tipo == "action" {
			msg.Device = deviceID
			sl.mu.Lock()
			h := sl.host
			sl.mu.Unlock()
			if h != nil {
				_ = h.EscreverJSON(msg)
			}
		}
	}
}

// acaoHTTP permite ao iPhone enviar uma resposta rápida cifrada (ex.: botão da notificação Push em
// segundo plano) numa única chamada HTTP POST, sem manter o WebSocket aberto.
func (s *Servidor) acaoHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !reIDValido.MatchString(id) {
		http.Error(w, `{"error":"id inválido"}`, http.StatusBadRequest)
		return
	}
	var msg Mensagem
	if err := json.NewDecoder(io.LimitReader(r.Body, 128*1024)).Decode(&msg); err != nil || !reIDValido.MatchString(msg.Device) || msg.Payload == "" {
		http.Error(w, `{"error":"pedido inválido"}`, http.StatusBadRequest)
		return
	}
	msg.Tipo = "action"
	if msg.ReqID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		msg.ReqID = hex.EncodeToString(b)
	}

	sl := s.obterSala(id)
	ch := make(chan Mensagem, 1)

	sl.mu.Lock()
	host := sl.host
	if host != nil {
		sl.pendentesHTTP[msg.ReqID] = ch
	}
	sl.mu.Unlock()

	if host == nil {
		http.Error(w, `{"error":"computador desligado"}`, http.StatusServiceUnavailable)
		return
	}
	defer func() {
		sl.mu.Lock()
		delete(sl.pendentesHTTP, msg.ReqID)
		sl.mu.Unlock()
	}()

	if err := host.EscreverJSON(msg); err != nil {
		http.Error(w, `{"error":"falha ao contactar computador"}`, http.StatusBadGateway)
		return
	}

	select {
	case resp := <-ch:
		w.Header().Set("Content-Type", "application/json")
		if resp.Status >= 200 && resp.Status < 600 {
			w.WriteHeader(resp.Status)
		}
		json.NewEncoder(w).Encode(resp)
	case <-time.After(6 * time.Second):
		http.Error(w, `{"error":"tempo limite esgotado"}`, http.StatusGatewayTimeout)
	case <-r.Context().Done():
	}
}

func (sl *sala) mensagemViewersSemLock() Mensagem {
	devs := make([]string, 0, len(sl.viewers))
	for id := range sl.viewers {
		devs = append(devs, id)
	}
	return Mensagem{
		Tipo:    "viewers",
		Count:   len(devs),
		Devices: devs,
	}
}

