package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"towerman/internal/relay"
)

func main() {
	padrao := strings.TrimSpace(os.Getenv("PORT"))
	if padrao == "" {
		padrao = "8080"
	}
	endereco := flag.String("addr", ":"+padrao, "endereço de escuta HTTP/WebSocket")
	certFile := flag.String("tls-cert", os.Getenv("TOWERMAN_RELAY_TLS_CERT"), "certificado TLS PEM opcional")
	keyFile := flag.String("tls-key", os.Getenv("TOWERMAN_RELAY_TLS_KEY"), "chave privada TLS PEM opcional")
	flag.Parse()

	apns, err := relay.NovoAPNsDeEnv()
	if err != nil {
		log.Fatalf("towerman-relay: configuração APNs inválida: %v", err)
	}
	if apns != nil {
		log.Printf("towerman-relay: cliente APNs ativo")
	}

	srvRelay := relay.NovoServidor(apns)
	httpSrv := &http.Server{
		Addr:              *endereco,
		Handler:           srvRelay.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, parar := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer parar()

	go func() {
		<-ctx.Done()
		desligar, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(desligar)
	}()

	log.Printf("towerman-relay: a escutar em %s", *endereco)
	if *certFile != "" && *keyFile != "" {
		err = httpSrv.ListenAndServeTLS(*certFile, *keyFile)
	} else {
		err = httpSrv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("towerman-relay: %v", err)
	}
}

