// Package tokenservice implements a minimal Wii U ACT (account) token issuer
// for Wii Party U. It transparently proxies every account request to the
// real upstream (Pretendo) EXCEPT nex_token/@me and service_token/@me
// requests for Wii Party U's own title IDs, which are answered locally so
// the console gets a valid, signed token instead of the generic
// "GAME_SERVER_ID_ENVIRONMENT_NOT_FOUND" (WiiU error 102-2482) that Pretendo
// returns for a title it has no server-id mapping for.
//
// It is a self-contained account stub: the only upstream dependency is the
// PNID profile lookup used to resolve the caller's PID.
package tokenservice

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PretendoNetwork/nex-go/v2/types"
	common_globals "github.com/PretendoNetwork/nex-protocols-common-go/v2/globals"
	"github.com/PretendoNetwork/plogger-go"
)

// GameServerConfig is the NEX auth server a given game_server_id should be
// pointed at, plus its title-ID allowlist.
type GameServerConfig struct {
	Host          string
	AuthPort      uint16
	AllowedTitles map[string]struct{}
}

type Config struct {
	Upstream       *url.URL
	GameServers    map[string]GameServerConfig // keyed by lowercase hex game_server_id
	KnownTitles    map[string]struct{}         // lowercase hex title IDs this server owns (gates service_token too)
	AESKey         []byte                      // 32 bytes, shared with the NEX auth/secure server
	PasswordSecret []byte                      // >=32 bytes, used to derive the NEX kerberos password from a PID
	TokenTTL       time.Duration
	RequestTimeout time.Duration
	ClientCertFile string
	ClientKeyFile  string
	Logger         *plogger.Logger
}

type nexTokenXML struct {
	XMLName     xml.Name `xml:"nex_token"`
	Host        string   `xml:"host"`
	NEXPassword string   `xml:"nex_password"`
	PID         uint32   `xml:"pid"`
	Port        uint16   `xml:"port"`
	Token       string   `xml:"token"`
}

type pnidProfileXML struct {
	XMLName xml.Name `xml:"person"`
	PID     uint32   `xml:"pid"`
}

type serviceTokenXML struct {
	XMLName xml.Name `xml:"service_token"`
	Token   string   `xml:"token"`
}

type Service struct {
	config Config
	proxy  *httputil.ReverseProxy
	client *http.Client
}

func New(config Config) (*Service, error) {
	if config.Upstream == nil || config.Upstream.Scheme != "https" {
		return nil, errors.New("upstream must be an HTTPS URL")
	}
	if len(config.GameServers) == 0 {
		return nil, errors.New("at least one game server is required")
	}
	for id, gs := range config.GameServers {
		if gs.Host == "" || gs.AuthPort == 0 {
			return nil, fmt.Errorf("game server %q: host and auth port are required", id)
		}
	}
	if len(config.AESKey) != 32 {
		return nil, errors.New("AES key must contain exactly 32 bytes")
	}
	if len(config.PasswordSecret) < 32 {
		return nil, errors.New("password secret must contain at least 32 bytes")
	}
	if config.TokenTTL == 0 {
		config.TokenTTL = 15 * time.Minute
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 10 * time.Second
	}
	if config.Logger == nil {
		config.Logger = plogger.NewLogger()
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if (config.ClientCertFile == "") != (config.ClientKeyFile == "") {
		return nil, errors.New("client certificate and key must be configured together")
	}
	if config.ClientCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
		transport.TLSClientConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
			Certificates: []tls.Certificate{certificate},
		}
	}

	proxy := httputil.NewSingleHostReverseProxy(config.Upstream)
	proxy.Transport = transport
	originalDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		originalDirector(request)
		request.Host = config.Upstream.Host
		request.Header.Del("X-Forwarded-For")
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		config.Logger.Errorf("[ACCOUNT] proxy failed for %s %s: %v", request.Method, request.URL.Path, err)
		http.Error(writer, "upstream account service unavailable", http.StatusBadGateway)
	}

	return &Service{
		config: config,
		proxy:  proxy,
		client: &http.Client{Timeout: config.RequestTimeout, Transport: transport},
	}, nil
}

func (service *Service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	service.config.Logger.Infof(
		"[ACCOUNT] %s %s?%s (title=%q, ua=%q)",
		request.Method, request.URL.Path, request.URL.RawQuery,
		request.Header.Get("X-Nintendo-Title-ID"), request.Header.Get("User-Agent"),
	)

	titleID := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(request.Header.Get("X-Nintendo-Title-ID")), "0x"))
	_, ownTitle := service.config.KnownTitles[titleID]

	switch {
	case request.URL.Path == "/v1/api/provider/nex_token/@me":
		requestedGameServerID := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("game_server_id")))
		if gameServer, ok := service.config.GameServers[requestedGameServerID]; ok {
			service.handleNEXToken(writer, request, gameServer, titleID)
			return
		}
	case request.URL.Path == "/v1/api/provider/service_token/@me" && ownTitle:
		service.handleServiceToken(writer, request, titleID)
		return
	}

	service.proxy.ServeHTTP(writer, request)
}

func (service *Service) handleNEXToken(writer http.ResponseWriter, request *http.Request, gameServer GameServerConfig, titleID string) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(gameServer.AllowedTitles) > 0 {
		if _, allowed := gameServer.AllowedTitles[titleID]; !allowed {
			service.config.Logger.Warningf("[TOKEN] rejected nex_token: title %q not allowed", titleID)
			http.Error(writer, "title not allowed", http.StatusForbidden)
			return
		}
	}

	pid, status, body, err := service.fetchPNIDProfile(request)
	if err != nil {
		if status != 0 && len(body) > 0 {
			writer.WriteHeader(status)
			_, _ = writer.Write(body)
		} else {
			service.config.Logger.Errorf("[TOKEN] profile verification failed: %v", err)
			http.Error(writer, "upstream account service unavailable", http.StatusBadGateway)
		}
		return
	}

	password, resultCode := passwordFromPID(service.config.PasswordSecret, types.NewPID(uint64(pid)))
	if resultCode != 0 {
		http.Error(writer, "credential service unavailable", http.StatusInternalServerError)
		return
	}

	token, err := issueToken(service.config.AESKey, pid, parseTitleID(titleID), service.config.TokenTTL)
	if err != nil {
		service.config.Logger.Errorf("[TOKEN] token generation failed: %v", err)
		http.Error(writer, "token generation failed", http.StatusInternalServerError)
		return
	}

	output, err := xml.Marshal(nexTokenXML{
		Host:        gameServer.Host,
		NEXPassword: password,
		PID:         pid,
		Port:        gameServer.AuthPort,
		Token:       token,
	})
	if err != nil {
		http.Error(writer, "token serialization failed", http.StatusInternalServerError)
		return
	}

	service.config.Logger.Successf("[TOKEN] nex_token issued PID=%d auth=%s:%d", pid, gameServer.Host, gameServer.AuthPort)
	writer.Header().Set("Content-Type", "text/xml; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Nintendo-Date", strconv.FormatInt(time.Now().UnixMilli(), 10))
	_, _ = writer.Write(output)
}

func (service *Service) handleServiceToken(writer http.ResponseWriter, request *http.Request, titleID string) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pid, status, body, err := service.fetchPNIDProfile(request)
	if err != nil {
		if status != 0 && len(body) > 0 {
			writer.WriteHeader(status)
			_, _ = writer.Write(body)
		} else {
			http.Error(writer, "upstream account service unavailable", http.StatusBadGateway)
		}
		return
	}

	issued := time.Now()
	expires := issued.Add(24 * time.Hour)
	token, err := issueServiceToken(service.config.AESKey, pid, parseTitleID(titleID), issued, expires)
	if err != nil {
		http.Error(writer, "service token generation failed", http.StatusInternalServerError)
		return
	}

	output, err := xml.Marshal(serviceTokenXML{Token: token})
	if err != nil {
		http.Error(writer, "service token serialization failed", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/xml; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(output)
	service.config.Logger.Successf("[SERVICE-TOKEN] issued PID=%d title=%s", pid, titleID)
}

func (service *Service) fetchPNIDProfile(request *http.Request) (uint32, int, []byte, error) {
	upstreamRequest := request.Clone(request.Context())
	upstreamRequest.URL.Scheme = service.config.Upstream.Scheme
	upstreamRequest.URL.Host = service.config.Upstream.Host
	upstreamRequest.URL.Path = "/v1/api/people/@me/profile"
	upstreamRequest.URL.RawPath = ""
	upstreamRequest.URL.RawQuery = ""
	upstreamRequest.Host = service.config.Upstream.Host
	upstreamRequest.RequestURI = ""
	upstreamRequest.Header.Del("X-Forwarded-For")

	response, err := service.client.Do(upstreamRequest)
	if err != nil {
		return 0, 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, response.StatusCode, body, err
	}
	if response.StatusCode != http.StatusOK {
		return 0, response.StatusCode, body, fmt.Errorf("profile rejected with HTTP %d", response.StatusCode)
	}
	pid, err := parsePNIDProfile(body)
	return pid, response.StatusCode, body, err
}

func parsePNIDProfile(body []byte) (uint32, error) {
	var profile pnidProfileXML
	if err := xml.Unmarshal(body, &profile); err != nil {
		return 0, err
	}
	if profile.XMLName.Local != "person" || profile.PID == 0 {
		return 0, errors.New("profile does not contain a valid PID")
	}
	return profile.PID, nil
}

func passwordFromPID(secret []byte, pid types.PID) (string, uint32) {
	if len(secret) < 32 {
		return "", 1
	}
	pidBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(pidBytes, uint64(pid))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(pidBytes)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), 0
}

func issueToken(key []byte, pid uint32, titleID uint64, ttl time.Duration) (string, error) {
	token := common_globals.NEXToken{
		SystemType:  1,
		TokenType:   3,
		UserPID:     pid,
		ExpireTime:  uint64(time.Now().Add(ttl).UnixMilli()),
		TitleID:     titleID,
		AccessLevel: 0,
	}

	var plain bytes.Buffer
	if err := binary.Write(&plain, binary.LittleEndian, token); err != nil {
		return "", err
	}

	padding := aes.BlockSize - plain.Len()%aes.BlockSize
	plain.Write(bytes.Repeat([]byte{byte(padding)}, padding))

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	encrypted := make([]byte, plain.Len())
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(encrypted, plain.Bytes())

	result := make([]byte, 4+len(encrypted))
	binary.BigEndian.PutUint32(result[:4], crc32.ChecksumIEEE(plain.Bytes()[:plain.Len()-padding]))
	copy(result[4:], encrypted)
	return base64.StdEncoding.EncodeToString(result), nil
}

func issueServiceToken(key []byte, pid uint32, titleID uint64, issued, expires time.Time) (string, error) {
	data := make([]byte, 28)
	binary.BigEndian.PutUint32(data[0:4], pid)
	binary.BigEndian.PutUint64(data[4:12], titleID)
	binary.BigEndian.PutUint64(data[12:20], uint64(issued.UnixMilli()))
	binary.BigEndian.PutUint64(data[20:28], uint64(expires.UnixMilli()))

	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return base64.StdEncoding.EncodeToString(append(data, mac.Sum(nil)...)), nil
}

func DecodeHexSecret(value string, expected int) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != expected {
		return nil, fmt.Errorf("secret must be %d bytes encoded as hexadecimal", expected)
	}
	return decoded, nil
}

func parseTitleID(value string) uint64 {
	titleID, _ := strconv.ParseUint(value, 16, 64)
	return titleID
}
