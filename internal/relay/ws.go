package relay

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const guidWS = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	opTexto = 0x1
	opBin   = 0x2
	opClose = 0x8
	opPing  = 0x9
	opPong  = 0xA
)

// ConnWS é uma ligação WebSocket RFC 6455 leve (sem dependências externas).
type ConnWS struct {
	conn    net.Conn
	r       *bufio.Reader
	mu      sync.Mutex
	cliente bool
	fechado bool
}

// AceitarWS promove um pedido HTTP para WebSocket (lado do servidor).
func AceitarWS(w http.ResponseWriter, r *http.Request) (*ConnWS, error) {
	chave := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || chave == "" {
		http.Error(w, "esperava WebSocket", http.StatusUpgradeRequired)
		return nil, errors.New("cabeçalho Upgrade ausente")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "sem suporte a hijack", http.StatusInternalServerError)
		return nil, errors.New("hijack indisponível")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	aceite := calcularChaveAceite(chave)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + aceite + "\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return &ConnWS{conn: conn, r: brw.Reader, cliente: false}, nil
}

// LigarWS abre uma ligação WebSocket como cliente (suporta ws://, wss://, http:// e https://).
func LigarWS(ctx context.Context, rawURL string, cabecalhos map[string]string) (*ConnWS, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	seguro := u.Scheme == "wss" || u.Scheme == "https"
	host := u.Host
	if !strings.Contains(host, ":") {
		if seguro {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	var d net.Dialer
	redeConn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	if seguro {
		tlsConn := tls.Client(redeConn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			redeConn.Close()
			return nil, err
		}
		redeConn = tlsConn
	}
	b := make([]byte, 16)
	rand.Read(b)
	chave := base64.StdEncoding.EncodeToString(b)
	caminho := u.RequestURI()
	if caminho == "" {
		caminho = "/"
	}
	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", caminho)
	fmt.Fprintf(&req, "Host: %s\r\n", u.Host)
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", chave)
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	for k, v := range cabecalhos {
		fmt.Fprintf(&req, "%s: %s\r\n", k, v)
	}
	req.WriteString("\r\n")

	if _, err := redeConn.Write([]byte(req.String())); err != nil {
		redeConn.Close()
		return nil, err
	}
	leitor := bufio.NewReader(redeConn)
	tp, err := http.ReadResponse(leitor, &http.Request{Method: http.MethodGet})
	if err != nil {
		redeConn.Close()
		return nil, err
	}
	if tp.StatusCode != http.StatusSwitchingProtocols {
		redeConn.Close()
		return nil, fmt.Errorf("handshake WebSocket recusado: %s", tp.Status)
	}
	if tp.Header.Get("Sec-WebSocket-Accept") != calcularChaveAceite(chave) {
		redeConn.Close()
		return nil, errors.New("Sec-WebSocket-Accept inválido")
	}
	return &ConnWS{conn: redeConn, r: leitor, cliente: true}, nil
}

func calcularChaveAceite(chave string) string {
	h := sha1.New()
	h.Write([]byte(chave + guidWS))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// LerJSON lê a próxima mensagem de texto/binário e descodifica o JSON.
func (c *ConnWS) LerJSON(v any) error {
	dados, err := c.LerMensagem()
	if err != nil {
		return err
	}
	return json.Unmarshal(dados, v)
}

// EscreverJSON codifica v em JSON e envia num frame de texto.
func (c *ConnWS) EscreverJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.EscreverTexto(b)
}

// EscreverTexto envia um frame de texto.
func (c *ConnWS) EscreverTexto(dados []byte) error {
	return c.escreverFrame(opTexto, dados)
}

// Ping envia um frame de controlo Ping.
func (c *ConnWS) Ping() error {
	return c.escreverFrame(opPing, nil)
}

// Fechar encerra a ligação WebSocket.
func (c *ConnWS) Fechar() error {
	c.mu.Lock()
	if c.fechado {
		c.mu.Unlock()
		return nil
	}
	c.fechado = true
	c.mu.Unlock()
	_ = c.escreverFrameSemLock(opClose, nil)
	return c.conn.Close()
}

// LerMensagem lê um frame completo (respondendo automaticamente a Pings).
func (c *ConnWS) LerMensagem() ([]byte, error) {
	var msgBuffer []byte
	for {
		 _ = c.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		cab := make([]byte, 2)
		if _, err := io.ReadFull(c.r, cab); err != nil {
			return nil, err
		}
		fin := (cab[0] & 0x80) != 0
		op := cab[0] & 0x0F
		mascarado := (cab[1] & 0x80) != 0
		tam := uint64(cab[1] & 0x7F)

		switch tam {
		case 126:
			ext := make([]byte, 2)
			if _, err := io.ReadFull(c.r, ext); err != nil {
				return nil, err
			}
			tam = uint64(binary.BigEndian.Uint16(ext))
		case 127:
			ext := make([]byte, 8)
			if _, err := io.ReadFull(c.r, ext); err != nil {
				return nil, err
			}
			tam = binary.BigEndian.Uint64(ext)
		}
		if tam > 4*1024*1024 {
			return nil, errors.New("frame WebSocket excede 4 MB")
		}
		var mascara [4]byte
		if mascarado {
			if _, err := io.ReadFull(c.r, mascara[:]); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, tam)
		if _, err := io.ReadFull(c.r, payload); err != nil {
			return nil, err
		}
		if mascarado {
			for i := range payload {
				payload[i] ^= mascara[i%4]
			}
		}

		switch op {
		case opClose:
			_ = c.Fechar()
			return nil, io.EOF
		case opPing:
			_ = c.escreverFrame(opPong, payload)
		case opPong:
			continue
		case opTexto, opBin, 0x0:
			msgBuffer = append(msgBuffer, payload...)
			if fin {
				return msgBuffer, nil
			}
		}
	}
}

func (c *ConnWS) escreverFrame(op byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fechado {
		return net.ErrClosed
	}
	return c.escreverFrameSemLock(op, payload)
}

func (c *ConnWS) escreverFrameSemLock(op byte, payload []byte) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	var cab []byte
	b0 := byte(0x80) | (op & 0x0F)
	cab = append(cab, b0)

	bitMascara := byte(0)
	if c.cliente {
		bitMascara = 0x80
	}
	n := len(payload)
	switch {
	case n < 126:
		cab = append(cab, bitMascara|byte(n))
	case n <= 65535:
		cab = append(cab, bitMascara|126, byte(n>>8), byte(n))
	default:
		cab = append(cab, bitMascara|127,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}

	if c.cliente {
		var mascara [4]byte
		rand.Read(mascara[:])
		cab = append(cab, mascara[:]...)
		copia := make([]byte, len(cab)+n)
		copy(copia, cab)
		for i := 0; i < n; i++ {
			copia[len(cab)+i] = payload[i] ^ mascara[i%4]
		}
		_, err := c.conn.Write(copia)
		return err
	}
	if _, err := c.conn.Write(cab); err != nil {
		return err
	}
	if n > 0 {
		_, err := c.conn.Write(payload)
		return err
	}
	return nil
}

