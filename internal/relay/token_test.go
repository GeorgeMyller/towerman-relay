package relay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func numSalas(s *Servidor) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.salas)
}

func TestHostExigeTokenDoRelay(t *testing.T) {
	srv := NovoServidor(nil)
	srv.ExigirTokens([]string{"token-a", " token-b "})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const segredo = "segredo-muito-longo-do-mac-01"
	for _, token := range []string{"", "token-c", "token-a-mais", "token-"} {
		cab := map[string]string{"X-Towerman-Host-Secret": segredo}
		if token != "" {
			cab[CabecalhoTokenRelay] = token
		}
		_, err := LigarWS(ctx, ts.URL+"/s/mac01/ws?role=host", cab)
		var eh *ErroHandshake
		if !errors.As(err, &eh) || eh.Status != http.StatusUnauthorized {
			t.Fatalf("token %q: esperava 401, obteve %v", token, err)
		}
	}
	if n := numSalas(srv); n != 0 {
		t.Fatalf("pedido recusado deixou %d sala(s) em memória", n)
	}

	ws, err := LigarWS(ctx, ts.URL+"/s/mac01/ws?role=host", map[string]string{
		"X-Towerman-Host-Secret": segredo,
		CabecalhoTokenRelay:      "token-b",
	})
	if err != nil {
		t.Fatalf("token válido recusado: %v", err)
	}
	defer ws.Fechar()
	var msg Mensagem
	if err := ws.LerJSON(&msg); err != nil || msg.Tipo != "viewers" {
		t.Fatalf("esperava viewers, obteve %+v (%v)", msg, err)
	}
	if n := numSalas(srv); n != 1 {
		t.Fatalf("esperava 1 sala, obteve %d", n)
	}
}

func TestRelaySemTokensFicaAberto(t *testing.T) {
	srv := NovoServidor(nil)
	if !srv.tokenHostValido("") || !srv.tokenHostValido("qualquer") {
		t.Fatal("sem tokens o relay deve aceitar qualquer host")
	}
	srv.ExigirTokens([]string{" ", ""})
	if !srv.tokenHostValido("") {
		t.Fatal("lista só com vazios deve deixar o relay aberto")
	}
	srv.ExigirTokens([]string{"x"})
	if srv.tokenHostValido("") || srv.tokenHostValido("y") || !srv.tokenHostValido("x") {
		t.Fatal("com tokens só o token certo passa")
	}
}

func TestTokensDeEnv(t *testing.T) {
	t.Setenv("TOWERMAN_RELAY_TOKENS", " a, ,b,,c ")
	if got := TokensDeEnv(); strings.Join(got, "|") != "a|b|c" {
		t.Fatalf("obteve %q", got)
	}
	t.Setenv("TOWERMAN_RELAY_TOKENS", "")
	if len(TokensDeEnv()) != 0 {
		t.Fatal("variável vazia deve dar lista vazia")
	}
}
