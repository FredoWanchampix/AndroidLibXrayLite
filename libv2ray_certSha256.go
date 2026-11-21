package libv2ray

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	stdnet "net"
	"reflect"
	"strconv"
	"time"

	quic "github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander"
)

type certSha256Request struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ServerName string `json:"serverName"`
	TimeoutMs  int64  `json:"timeoutMs"`

	// Поля обфускации QUIC (добавлены форком FredoWanchampix).
	//
	// Зачем: нативная fetchQUICCertSha256 раньше делала ЧИСТОЕ QUIC-рукопожатие
	// (quic.DialAddr). Серверы Hysteria2 с обфускацией salamander/gecko ждут
	// обфусцированные пакеты и молча роняют «голое» рукопожатие, поэтому клиент
	// получал «context deadline exceeded» для всех obfs-профилей (вещдок
	// 20.11.2026: 21 из 21 QUIC-отказа — профили с obfs=salamander, 4 из 4
	// успеха — без obfs).
	//
	// Обфускация применяется кодом САМОГО xray-core (пакет
	// transport/internet/finalmask/salamander), а не собственной реализацией,
	// поэтому поведение байт-в-байт совпадает с тем, что делает ядро при работе
	// профиля. Сервер провайдера не видит никакой разницы: менять на серверах
	// ничего не нужно.
	//
	// Пустой Obfs = прежнее поведение (чистое QUIC), обратная совместимость
	// сохранена полностью.
	Obfs          string `json:"obfs"`
	ObfsPassword  string `json:"obfsPassword"`
	MinPacketSize int32  `json:"minPacketSize"`
	MaxPacketSize int32  `json:"maxPacketSize"`
}

type certSha256Result struct {
	Sha256 string `json:"sha256"`
	Error  string `json:"error"`
}

func FetchTlsCertSha256(requestJSON string) string {
	return fetchCertSha256(requestJSON, fetchTLSCertSha256)
}

func FetchQuicCertSha256(requestJSON string) string {
	return fetchCertSha256(requestJSON, fetchQUICCertSha256)
}

func fetchCertSha256(
	requestJSON string,
	fetcher func(certSha256Request) (string, error),
) string {
	var request certSha256Request
	if err := json.Unmarshal([]byte(requestJSON), &request); err != nil {
		return marshalCertSha256Result(certSha256Result{Error: err.Error()})
	}

	sha256Value, err := fetcher(request)
	if err != nil {
		return marshalCertSha256Result(certSha256Result{Error: err.Error()})
	}

	return marshalCertSha256Result(certSha256Result{Sha256: sha256Value})
}

func fetchTLSCertSha256(request certSha256Request) (string, error) {
	address, serverName, timeout, err := normalizeCertRequest(request)
	if err != nil {
		return "", err
	}

	conn, err := tls.DialWithDialer(
		&stdnet.Dialer{Timeout: timeout},
		"tcp",
		address,
		&tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("peer certificate is empty")
	}

	return rawCertSHA256Hex(state.PeerCertificates[0].Raw), nil
}

func fetchQUICCertSha256(request certSha256Request) (string, error) {
	address, serverName, timeout, err := normalizeCertRequest(request)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h3"},
	}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       timeout,
	}

	// Профиль БЕЗ обфускации: прежнее поведение, чистое QUIC-рукопожатие.
	if !hasObfuscation(request) {
		return dialPlainQUIC(ctx, address, tlsConfig, quicConfig)
	}

	return dialObfuscatedQUIC(ctx, request, address, timeout, tlsConfig, quicConfig)
}

// hasObfuscation сообщает, задана ли обфускация QUIC в запросе.
//
// Обфускация включена, когда тип obfs непустой и не "none", И пароль непустой
// (без пароля salamander не работает — xray-core требует PSK >= 4 байт).
// Неизвестный тип здесь НЕ отсекается намеренно: он доходит до buildUDPMask и
// даёт ЯВНУЮ ошибку "unsupported obfs type", а не молчаливый plain-QUIC с
// последующим «context deadline exceeded». Молчаливая деградация хуже честной
// диагностики: пользователь увидел бы таймаут и не понял бы причину.
func hasObfuscation(request certSha256Request) bool {
	if request.ObfsPassword == "" {
		return false
	}
	return normalizeObfsType(request.Obfs) != obfsNone
}

const (
	obfsNone       = ""
	obfsSalamander = "salamander"
	obfsGecko      = "gecko"
)

// normalizeObfsType приводит тип обфускации к каноническому виду.
// Панели и подписки присылают значение в разном регистре, поэтому сравнение
// регистронезависимое. Пустое значение = отсутствие обфускации.
func normalizeObfsType(obfs string) string {
	switch obfs {
	case "salamander", "Salamander", "SALAMANDER":
		return obfsSalamander
	case "gecko", "Gecko", "GECKO":
		return obfsGecko
	case "", "none", "None", "NONE":
		return obfsNone
	default:
		// Полный регистронезависимый разбор для прочих написаний.
		lowered := toLowerASCII(obfs)
		switch lowered {
		case obfsSalamander:
			return obfsSalamander
		case obfsGecko:
			return obfsGecko
		default:
			return lowered
		}
	}
}

func toLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// dialPlainQUIC выполняет обычное QUIC-рукопожатие (поведение до появления
// поддержки обфускации).
func dialPlainQUIC(
	ctx context.Context,
	address string,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
) (string, error) {
	conn, err := quic.DialAddr(ctx, address, tlsConfig, quicConfig)
	if err != nil {
		return "", err
	}
	defer conn.CloseWithError(0, "")

	return certSha256FromQUICConn(conn)
}

// dialObfuscatedQUIC выполняет QUIC-рукопожатие поверх обфускации
// salamander/gecko, используя механизмы самого xray-core.
//
// Последовательность повторяет transport/internet/hysteria/dialer.go:
//  1. finalmask.NewFinalMask с одной UDP-маской (как в
//     transport/internet/memory_settings.go) — обёртка выбирается по типу:
//     salamander.Config реализует HeaderConn и обрабатывается через
//     headerManagerConn, GeckoConfig — обычным WrapPacketConnClient. Оба пути
//     реализованы самим ядром, поэтому формат пакетов совпадает с сервером.
//  2. FinalMask.DialUDP даёт уже обфусцированный PacketConn.
//  3. quic.Transport{Conn: pktConn, DisableGSO: true}.Dial — GSO ОБЯЗАТЕЛЬНО
//     выключен: пакеты переписываются после выхода из стека (salamander
//     добавляет 8-байтный salt, gecko ещё и фрагментирует), а GSO объединяет
//     сегменты, и переписывание повредило бы каждый из них. Используется Dial,
//     а не DialEarly: нужен ЗАВЕРШЁННЫЙ handshake, иначе сертификат пуст.
func dialObfuscatedQUIC(
	ctx context.Context,
	request certSha256Request,
	address string,
	timeout time.Duration,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
) (string, error) {
	udpMask, err := buildUDPMask(request)
	if err != nil {
		return "", err
	}

	dest, err := buildUDPDestination(address)
	if err != nil {
		return "", err
	}

	fm := finalmask.NewFinalMask(
		nil,
		[]finalmask.UDPMask{udpMask},
		func(ctx context.Context, d net.Destination) (net.Conn, error) {
			return internet.DialSystem(ctx, d, nil)
		},
		func(ctx context.Context, addr net.Addr) (net.Listener, error) {
			return internet.ListenSystem(ctx, addr, nil)
		},
		func(ctx context.Context, d net.Destination) (net.PacketConn, net.Addr, error) {
			return dialSystemUDP(ctx, d)
		},
		func(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
			return internet.ListenSystemPacket(ctx, addr, nil)
		},
	)

	wrapped, err := fm.DialUDP(ctx, dest)
	if err != nil {
		return "", errors.New("failed to dial obfuscated udp: " + err.Error())
	}
	wrapper, ok := wrapped.(*net.PacketConnWrapper)
	if !ok {
		return "", errors.New("unexpected packet conn type from finalmask: " + reflect.TypeOf(wrapped).String())
	}
	pktConn := wrapper.PacketConn
	udpAddr := wrapper.RemoteAddr()

	// Таймаут рукопожатия уже задан в quicConfig; дополнительно ограничиваем
	// весь dial, чтобы зависший обфусцированный обмен не держал вызов дольше
	// отведённого времени.
	dialCtx, cancelDial := context.WithTimeout(ctx, timeout)
	defer cancelDial()

	tr := &quic.Transport{
		Conn:       pktConn,
		DisableGSO: true,
	}

	// Dial, а НЕ DialEarly (важно). DialEarly возвращает соединение до
	// завершения TLS-рукопожатия (0-RTT), и ConnectionState().TLS.PeerCertificates
	// в этот момент ещё ПУСТ — функция вернула бы «peer certificate is empty»
	// на полностью рабочем сервере. Ядро в hysteria/dialer.go использует
	// DialEarly, но затем ждёт HTTP-ответ, то есть полное рукопожатие; нам же
	// сертификат нужен сразу, поэтому ждём handshake явно.
	conn, err := tr.Dial(dialCtx, udpAddr, tlsConfig, quicConfig)
	if err != nil {
		// Порядок закрытия ВАЖЕН и совпадает с transport/internet/hysteria:
		// сначала Transport (его внутренние горутины пишут в сокет), затем сам
		// сокет. Обратный порядок (как дали бы defer'ы) привёл бы к записи в
		// уже закрытый PacketConn.
		tr.Close()
		pktConn.Close()
		return "", err
	}

	sha, certErr := certSha256FromQUICConn(conn)
	conn.CloseWithError(0, "")
	tr.Close()
	pktConn.Close()
	return sha, certErr
}

// buildUDPMask создаёт UDP-маску обфускации средствами xray-core.
//
// gecko отличается от salamander наличием размеров пакетов (фрагментация
// long-header пакетов), поэтому выбор делается по типу, а значения размеров
// берутся из запроса. Нули xray-core заменяет своими умолчаниями (512/1200).
func buildUDPMask(request certSha256Request) (finalmask.UDPMask, error) {
	switch normalizeObfsType(request.Obfs) {
	case obfsSalamander:
		return &salamander.Config{Password: request.ObfsPassword}, nil
	case obfsGecko:
		return &salamander.GeckoConfig{
			Password:      request.ObfsPassword,
			MinPacketSize: request.MinPacketSize,
			MaxPacketSize: request.MaxPacketSize,
		}, nil
	default:
		return nil, errors.New("unsupported obfs type: " + request.Obfs)
	}
}

// buildUDPDestination разбирает "host:port" в net.Destination для UDP.
func buildUDPDestination(address string) (net.Destination, error) {
	host, portStr, err := stdnet.SplitHostPort(address)
	if err != nil {
		return net.Destination{}, errors.New("invalid address: " + err.Error())
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return net.Destination{}, errors.New("invalid port: " + portStr)
	}
	return net.UDPDestination(net.ParseAddress(host), net.Port(port)), nil
}

// dialSystemUDP повторяет логику transport/internet/memory_settings.go:
// DialSystem для UDP-цели возвращает либо PacketConnWrapper, либо
// cnc.Connection, который оборачивается в FakePacketConn.
func dialSystemUDP(ctx context.Context, dest net.Destination) (net.PacketConn, net.Addr, error) {
	conn, err := internet.DialSystem(ctx, dest, nil)
	if err != nil {
		return nil, nil, err
	}
	switch c := conn.(type) {
	case *net.PacketConnWrapper:
		return c.PacketConn, c.RemoteAddr(), nil
	case *cnc.Connection:
		return &internet.FakePacketConn{Conn: c}, &net.UDPAddr{IP: []byte{0, 0, 0, 0}, Port: 0}, nil
	default:
		_ = conn.Close()
		return nil, nil, errors.New("unexpected conn type for udp dial: " + reflect.TypeOf(conn).String())
	}
}

// certSha256FromQUICConn извлекает SHA-256 leaf-сертификата из установленного
// QUIC-соединения.
func certSha256FromQUICConn(conn *quic.Conn) (string, error) {
	state := conn.ConnectionState()
	if len(state.TLS.PeerCertificates) == 0 {
		return "", errors.New("peer certificate is empty")
	}

	return rawCertSHA256Hex(state.TLS.PeerCertificates[0].Raw), nil
}

func normalizeCertRequest(req certSha256Request) (string, string, time.Duration, error) {
	if req.Address == "" {
		return "", "", 0, errors.New("address is empty")
	}

	port := req.Port
	if port <= 0 {
		port = 443
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond

	return net.JoinHostPort(req.Address, strconv.Itoa(port)), req.ServerName, timeout, nil
}

func rawCertSHA256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func marshalCertSha256Result(result certSha256Result) string {
	data, err := json.Marshal(result)
	if err != nil {
		return `{"error":"failed to marshal result"}`
	}
	return string(data)
}
