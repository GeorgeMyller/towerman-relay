package relay

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Sem tópico padrão: com APNs configurado, falta de APNS_TOPIC é erro claro no arranque.
func TestAPNsSemTopicoDaErro(t *testing.T) {
	t.Setenv("APNS_KEY_ID", "KEY1234567")
	t.Setenv("APNS_TEAM_ID", "TEAM123456")
	t.Setenv("APNS_KEY_P8", gerarChaveP8Teste(t))
	t.Setenv("APNS_TOPIC", "")
	if cli, err := NovoAPNsDeEnv(); err == nil || cli != nil || !strings.Contains(err.Error(), "APNS_TOPIC") {
		t.Fatalf("esperava erro sobre APNS_TOPIC, obteve %v, %v", cli, err)
	}
	t.Setenv("APNS_TOPIC", "com.example.towerman")
	if cli, err := NovoAPNsDeEnv(); err != nil || cli == nil {
		t.Fatalf("com tópico esperava cliente, obteve %v, %v", cli, err)
	}
	if _, err := NovoAPNs(ConfigAPNs{KeyID: "K", TeamID: "T", ChavePEM: gerarChaveP8Teste(t)}); err == nil {
		t.Fatal("NovoAPNs sem tópico deve falhar")
	}
	t.Setenv("APNS_KEY_ID", "")
	if cli, err := NovoAPNsDeEnv(); err != nil || cli != nil {
		t.Fatalf("sem APNs configurado esperava nil, nil; obteve %v, %v", cli, err)
	}
}

// Um push de decisão leva o conteúdo cifrado e pede à extensão do iPhone que o decifre; o texto
// em claro é só o genérico.
func TestPushDeDecisaoCifrado(t *testing.T) {
	var corpo map[string]any
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		corpo = nil
		json.Unmarshal(b, &corpo)
		w.WriteHeader(http.StatusOK)
	}))
	defer mock.Close()
	cli, err := NovoAPNs(ConfigAPNs{KeyID: "KEY1234567", TeamID: "TEAM123456", Topic: "t", ChavePEM: gerarChaveP8Teste(t), Endpoint: mock.URL})
	if err != nil {
		t.Fatal(err)
	}

	p := PedidoPush{Token: "tk", Titulo: "Towerman", Corpo: "Uma sessão espera uma decisão.", Categoria: "decisao",
		AgentID: "s", PromptID: "d1", Enc: "CIFRADO", Device: "dev", Server: "srv"}
	if err := cli.Enviar(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	aps, _ := corpo["aps"].(map[string]any)
	if aps["mutable-content"] != float64(1) || corpo["enc"] != "CIFRADO" || corpo["device"] != "dev" || corpo["server"] != "srv" {
		t.Fatalf("payload: %v", corpo)
	}

	// Sem Enc, o payload fica como antes (permissões).
	p.Enc = ""
	if err := cli.Enviar(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	aps, _ = corpo["aps"].(map[string]any)
	if _, tem := aps["mutable-content"]; tem || corpo["enc"] != nil {
		t.Fatalf("payload sem enc: %v", corpo)
	}
}
