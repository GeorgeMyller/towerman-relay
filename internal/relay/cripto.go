package relay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const infoHKDF = "towerman-e2ee-v1"

// CarregarOuCriarChaveX25519 lê a chave privada X25519 em <home>/relay-key ou gera uma nova.
func CarregarOuCriarChaveX25519(home string) (*ecdh.PrivateKey, string, error) {
	caminho := filepath.Join(home, "relay-key")
	curva := ecdh.X25519()
	if dados, err := os.ReadFile(caminho); err == nil {
		b, err := descodificarB64(strings.TrimSpace(string(dados)))
		if err == nil {
			if priv, err := curva.NewPrivateKey(b); err == nil {
				return priv, codificarB64(priv.PublicKey().Bytes()), nil
			}
		}
	}
	priv, err := curva.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	_ = os.MkdirAll(home, 0o700)
	_ = os.WriteFile(caminho, []byte(codificarB64(priv.Bytes())), 0o600)
	return priv, codificarB64(priv.PublicKey().Bytes()), nil
}

// GerarParX25519 cria um par de chaves X25519 efémero ou para testes/clientes.
func GerarParX25519() (*ecdh.PrivateKey, string, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	return priv, codificarB64(priv.PublicKey().Bytes()), nil
}

// DerivarChaveSimetrica calcula ECDH X25519 + HKDF-SHA256 (32 bytes) compatível com o CryptoKit da Apple.
func DerivarChaveSimetrica(priv *ecdh.PrivateKey, peerPubB64 string, serverID string) ([]byte, error) {
	pubBytes, err := descodificarB64(peerPubB64)
	if err != nil {
		return nil, err
	}
	peerPub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	segredo, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	return hkdfSHA256(segredo, []byte(serverID), []byte(infoHKDF), 32)
}

// Selar cifra o texto claro com AES-256-GCM e devolve base64url(nonce[12] || ciphertext || tag[16]).
// O formato combinado coincide com AES.GCM.SealedBox.combined do CryptoKit da Apple.
func Selar(chave []byte, claro []byte, aad []byte) (string, error) {
	bloco, err := aes.NewCipher(chave)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(bloco)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	combinado := gcm.Seal(nonce, nonce, claro, aad)
	return codificarB64(combinado), nil
}

// Abrir valida a tag AES-256-GCM e decifra base64url(nonce[12] || ciphertext || tag[16]).
func Abrir(chave []byte, cifradoB64 string, aad []byte) ([]byte, error) {
	combinado, err := descodificarB64(cifradoB64)
	if err != nil {
		return nil, err
	}
	bloco, err := aes.NewCipher(chave)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(bloco)
	if err != nil {
		return nil, err
	}
	tamNonce := gcm.NonceSize()
	if len(combinado) < tamNonce+gcm.Overhead() {
		return nil, errors.New("payload cifrado truncado")
	}
	nonce, cifrado := combinado[:tamNonce], combinado[tamNonce:]
	return gcm.Open(nil, nonce, cifrado, aad)
}

// hkdfSHA256 implementa RFC 5869 (Extract + Expand com SHA-256).
func hkdfSHA256(segredo, salt, info []byte, tamanho int) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extrator := hmac.New(sha256.New, salt)
	extrator.Write(segredo)
	prk := extrator.Sum(nil)

	var okm []byte
	var anterior []byte
	contador := byte(1)
	for len(okm) < tamanho {
		h := hmac.New(sha256.New, prk)
		h.Write(anterior)
		h.Write(info)
		h.Write([]byte{contador})
		anterior = h.Sum(nil)
		okm = append(okm, anterior...)
		contador++
	}
	return bytes.Clone(okm[:tamanho]), nil
}

func codificarB64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func descodificarB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "+/") {
		return base64.RawStdEncoding.DecodeString(s)
	}
	return base64.RawURLEncoding.DecodeString(s)
}

