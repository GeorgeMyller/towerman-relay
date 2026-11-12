package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCriptoX25519AESGCM(t *testing.T) {
	privMac, pubMac, err := GerarParX25519()
	if err != nil {
		t.Fatal(err)
	}
	privPhone, pubPhone, err := GerarParX25519()
	if err != nil {
		t.Fatal(err)
	}
	serverID := "srv-12345678"
	chaveMac, err := DerivarChaveSimetrica(privMac, pubPhone, serverID)
	if err != nil {
		t.Fatal(err)
	}
	chavePhone, err := DerivarChaveSimetrica(privPhone, pubMac, serverID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chaveMac, chavePhone) {
		t.Fatal("chaves derivadas diferentes")
	}

	aad := []byte("dev-abcd")
	original := []byte(`{"server":{"id":"srv-12345678"},"agents":[]}`)
	cifrado, err := Selar(chaveMac, original, aad)
	if err != nil {
		t.Fatal(err)
	}
	decifrado, err := Abrir(chavePhone, cifrado, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, decifrado) {
		t.Fatalf("esperava %s, obteve %s", original, decifrado)
	}

	// Adulterar o AAD deve falhar na verificação da tag GCM.
	if _, err := Abrir(chavePhone, cifrado, []byte("dev-outro")); err == nil {
		t.Fatal("esperava falha com AAD diferente")
	}
}

func gerarChaveP8Teste(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestRelayFluxoCompletoEconomiaCota(t *testing.T) {
	var pushesRecebidos atomic.Int32
	apnsMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/3/device/") && strings.HasPrefix(r.Header.Get("Authorization"), "bearer ") {
			pushesRecebidos.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer apnsMock.Close()

	apnsCli, err := NovoAPNs(ConfigAPNs{
		KeyID:    "KEY1234567",
		TeamID:   "TEAM123456",
		Topic:    "com.example.towerman",
		ChavePEM: gerarChaveP8Teste(t),
		Endpoint: apnsMock.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := NovoServidor(apnsCli)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Antes do Mac ligar, /s/mac01/health devolve 503.
	resp, err := http.Get(ts.URL + "/s/mac01/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("esperava 503 sem host, obteve %d", resp.StatusCode)
	}

	// 2. O Mac liga-se como host e recebe viewers == 0.
	wsHost, err := LigarWS(ctx, ts.URL+"/s/mac01/ws?role=host", map[string]string{
		"X-Towerman-Host-Secret": "segredo-muito-longo-do-mac-01",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wsHost.Fechar()

	var msgInicial Mensagem
	if err := wsHost.LerJSON(&msgInicial); err != nil {
		t.Fatal(err)
	}
	if msgInicial.Tipo != "viewers" || msgInicial.Count != 0 {
		t.Fatalf("esperava viewers=0, obteve %+v", msgInicial)
	}

	// 3. Com viewers == 0, o Mac envia push_wake para acordar o iPhone via APNs.
	if err := wsHost.EscreverJSON(Mensagem{
		Tipo: "push_wake",
		Pushes: []PedidoPush{{
			Token:    "apns-token-iphone",
			Titulo:   "Claude · Mac",
			Corpo:    "Bash?",
			AgentID:  "ag1",
			PromptID: "42",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	prazo := time.Now().Add(2 * time.Second)
	for pushesRecebidos.Load() == 0 && time.Now().Before(prazo) {
		time.Sleep(20 * time.Millisecond)
	}
	if pushesRecebidos.Load() != 1 {
		t.Fatalf("esperava 1 push APNs enviado, obteve %d", pushesRecebidos.Load())
	}

	// 4. O iPhone abre o ecrã e liga-se como viewer: o Mac recebe imediatamente viewers == 1.
	wsViewer, err := LigarWS(ctx, ts.URL+"/s/mac01/ws?role=viewer&device=iphone01", nil)
	if err != nil {
		t.Fatal(err)
	}
	var msgViewerEntrou Mensagem
	if err := wsHost.LerJSON(&msgViewerEntrou); err != nil {
		t.Fatal(err)
	}
	if msgViewerEntrou.Tipo != "viewers" || msgViewerEntrou.Count != 1 || len(msgViewerEntrou.Devices) != 1 || msgViewerEntrou.Devices[0] != "iphone01" {
		t.Fatalf("esperava viewers=1 [iphone01], obteve %+v", msgViewerEntrou)
	}

	// 5. O iPhone fecha o app (bloqueia o ecrã): o Mac recebe viewers == 0 para voltar ao silêncio.
	_ = wsViewer.Fechar()
	var msgViewerSaiu Mensagem
	if err := wsHost.LerJSON(&msgViewerSaiu); err != nil {
		t.Fatal(err)
	}
	if msgViewerSaiu.Tipo != "viewers" || msgViewerSaiu.Count != 0 {
		t.Fatalf("esperava viewers=0 após fechar iPhone, obteve %+v", msgViewerSaiu)
	}

	// 6. Com o iPhone bloqueado, o utilizador toca em "Permitir" na notificação (POST /s/mac01/action).
	go func() {
		var acao Mensagem
		if err := wsHost.LerJSON(&acao); err == nil && acao.Tipo == "action" {
			_ = wsHost.EscreverJSON(Mensagem{
				Tipo:    "action_reply",
				ReqID:   acao.ReqID,
				Device:  acao.Device,
				Status:  http.StatusNoContent,
				Payload: "resposta-cifrada",
			})
		}
	}()

	corpoAcao, _ := json.Marshal(Mensagem{
		Device:  "iphone01",
		Payload: "acao-cifrada",
	})
	respAcao, err := http.Post(ts.URL+"/s/mac01/action", "application/json", bytes.NewReader(corpoAcao))
	if err != nil {
		t.Fatal(err)
	}
	defer respAcao.Body.Close()
	if respAcao.StatusCode != http.StatusNoContent {
		t.Fatalf("esperava 204 da ação via HTTP, obteve %d", respAcao.StatusCode)
	}
}

func TestRelayNaoCriaSalaSemHost(t *testing.T) {
	srv := NovoServidor(nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/s/sala-inexistente/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("health sem host devia dar 503, obteve %d", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := LigarWS(ctx, ts.URL+"/s/sala-inexistente/ws?role=viewer&device=iphone01", nil); err == nil {
		t.Fatal("viewer sem host devia ser recusado")
	}

	corpo, _ := json.Marshal(Mensagem{Device: "iphone01", Payload: "abc"})
	respAcao, err := http.Post(ts.URL+"/s/sala-inexistente/action", "application/json", bytes.NewReader(corpo))
	if err != nil {
		t.Fatal(err)
	}
	respAcao.Body.Close()
	if respAcao.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("action sem host devia dar 503, obteve %d", respAcao.StatusCode)
	}

	if n := numSalas(srv); n != 0 {
		t.Fatalf("pedidos sem host deixaram %d sala(s) em memória", n)
	}
}

func TestLerMensagemLimitaBufferFragmentado(t *testing.T) {
	a, b := netPipeWS(t)
	defer a.conn.Close()
	defer b.conn.Close()

	// Escrita numa goroutine: net.Pipe() não tem buffer e LerMensagem recusa o 2.º frame antes de ler o payload.
	go func() {
		pedaco := make([]byte, 2*1024*1024+512*1024)
		if err := escreverFrameBruto(a, opTexto, false, pedaco); err != nil {
			return
		}
		_ = escreverFrameBruto(a, 0x0, true, pedaco)
	}()

	_, err := b.LerMensagem()
	if err == nil || !strings.Contains(err.Error(), "excede") {
		t.Fatalf("esperava erro de limite de mensagem, obteve %v", err)
	}
}

func netPipeWS(t *testing.T) (*ConnWS, *ConnWS) {
	t.Helper()
	c1, c2 := net.Pipe()
	return &ConnWS{conn: c1, r: bufio.NewReader(c1), cliente: true},
		&ConnWS{conn: c2, r: bufio.NewReader(c2), cliente: false}
}

func escreverFrameBruto(c *ConnWS, op byte, fin bool, payload []byte) error {
	var b0 byte = op & 0x0F
	if fin {
		b0 |= 0x80
	}
	n := len(payload)
	cab := []byte{b0}
	switch {
	case n < 126:
		cab = append(cab, byte(n))
	case n <= 65535:
		cab = append(cab, 126, byte(n>>8), byte(n))
	default:
		cab = append(cab, 127,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	if _, err := c.conn.Write(cab); err != nil {
		return err
	}
	_, err := c.conn.Write(payload)
	return err
}
