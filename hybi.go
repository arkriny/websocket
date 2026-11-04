// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

// This file implements a protocol of hybi draft.
// http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	closeStatusNormal            = 1000
	closeStatusGoingAway         = 1001
	closeStatusProtocolError     = 1002
	closeStatusUnsupportedData   = 1003
	closeStatusFrameTooLarge     = 1004
	closeStatusNoStatusRcvd      = 1005
	closeStatusAbnormalClosure   = 1006
	closeStatusBadMessageData    = 1007
	closeStatusPolicyViolation   = 1008
	closeStatusTooBigData        = 1009
	closeStatusExtensionMismatch = 1010

	maxControlFramePayloadLength = 125
)

var (
	ErrBadMaskingKey         = &ProtocolError{"bad masking key"}
	ErrBadPongMessage        = &ProtocolError{"bad pong message"}
	ErrBadClosingStatus      = &ProtocolError{"bad closing status"}
	ErrUnsupportedExtensions = &ProtocolError{"unsupported extensions"}
	ErrNotImplemented        = &ProtocolError{"not implemented"}

	handshakeHeader = map[string]bool{
		"Host":                   true,
		"Upgrade":                true,
		"Connection":             true,
		"Sec-Websocket-Key":      true,
		"Sec-Websocket-Origin":   true,
		"Sec-Websocket-Version":  true,
		"Sec-Websocket-Protocol": true,
		"Sec-Websocket-Accept":   true,
	}
)

// A frameHeader is a frame header.
type frameHeader struct {
	Fin        bool
	Rsv        [3]bool
	OpCode     byte
	Length     int64
	MaskingKey []byte

	data *bytes.Buffer
}

// A frameReader is a reader for frame.
type frameReader struct {
	reader io.Reader

	header frameHeader
	pos    int64
	length int
}

func (frame *frameReader) Read(msg []byte) (int, error) {
	n, err := frame.reader.Read(msg)
	if frame.header.MaskingKey != nil {
		for i := range n {
			msg[i] ^= frame.header.MaskingKey[frame.pos%4]
			frame.pos++
		}
	}
	return n, err
}

// PayloadType returns payload type.
func (frame *frameReader) PayloadType() byte { return frame.header.OpCode }

// HeaderReader returns a reader to read header of the frame.
func (frame *frameReader) HeaderReader() io.Reader {
	if frame.header.data == nil {
		return nil
	}
	if frame.header.data.Len() == 0 {
		return nil
	}
	return frame.header.data
}

// Len returns total length of the frame, including header and trailer.
func (frame *frameReader) Len() int { return frame.length }

// A frameReaderFactory creates new frame reader based on its frame type.
type frameReaderFactory struct {
	*bufio.Reader
}

// NewFrameReader reads a frame header from the connection, and creates new reader for the frame.
// See Section 5.2 Base Framing protocol for detail.
// http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17#section-5.2
func (buf frameReaderFactory) NewFrameReader() (*frameReader, error) {
	var frame frameReader
	var header []byte
	// First byte. FIN/RSV1/RSV2/RSV3/OpCode(4bits)
	b, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	header = append(header, b)
	frame.header.Fin = ((header[0] >> 7) & 1) != 0
	for i := range 3 {
		j := uint(6 - i)
		frame.header.Rsv[i] = ((header[0] >> j) & 1) != 0
	}
	frame.header.OpCode = header[0] & 0x0f

	// Second byte. Mask/Payload len(7bits)
	b, err = buf.ReadByte()
	if err != nil {
		return nil, err
	}
	header = append(header, b)
	mask := (b & 0x80) != 0
	b &= 0x7f
	lengthFields := 0
	switch {
	case b <= 125: // Payload length 7bits.
		frame.header.Length = int64(b)
	case b == 126: // Payload length 7+16bits
		lengthFields = 2
	case b == 127: // Payload length 7+64bits
		lengthFields = 8
	}
	for i := range lengthFields {
		b, err := buf.ReadByte()
		if err != nil {
			return nil, err
		}
		if lengthFields == 8 && i == 0 { // MSB must be zero when 7+64 bits
			b &= 0x7f
		}
		header = append(header, b)
		frame.header.Length = frame.header.Length*256 + int64(b)
	}
	if mask {
		// Masking key. 4 bytes.
		for range 4 {
			b, err := buf.ReadByte()
			if err != nil {
				return nil, err
			}
			header = append(header, b)
			frame.header.MaskingKey = append(frame.header.MaskingKey, b)
		}
	}
	frame.reader = io.LimitReader(buf.Reader, frame.header.Length)
	frame.header.data = bytes.NewBuffer(header)
	frame.length = len(header) + int(frame.header.Length)
	return &frame, nil
}

// A frameWriter is a writer for frame.
type frameWriter struct {
	writer *bufio.Writer

	header *frameHeader
}

func (frame *frameWriter) Write(msg []byte) (int, error) {
	var header []byte
	var b byte
	if frame.header.Fin {
		b |= 0x80
	}
	for i := range 3 {
		if frame.header.Rsv[i] {
			j := uint(6 - i)
			b |= 1 << j
		}
	}
	b |= frame.header.OpCode
	header = append(header, b)
	if frame.header.MaskingKey != nil {
		b = 0x80
	} else {
		b = 0
	}
	lengthFields := 0
	length := len(msg)
	switch {
	case length <= 125:
		b |= byte(length)
	case length < 65536:
		b |= 126
		lengthFields = 2
	default:
		b |= 127
		lengthFields = 8
	}
	header = append(header, b)
	for i := range lengthFields {
		j := uint((lengthFields - i - 1) * 8)
		b = byte((length >> j) & 0xff)
		header = append(header, b)
	}
	if frame.header.MaskingKey != nil {
		if len(frame.header.MaskingKey) != 4 {
			return 0, ErrBadMaskingKey
		}
		header = append(header, frame.header.MaskingKey...)
		frame.writer.Write(header)
		data := make([]byte, length)
		for i := range data {
			data[i] = msg[i] ^ frame.header.MaskingKey[i%4]
		}
		frame.writer.Write(data)
		err := frame.writer.Flush()
		return length, err
	}
	frame.writer.Write(header)
	frame.writer.Write(msg)
	err := frame.writer.Flush()
	return length, err
}

func (frame *frameWriter) Close() error { return nil }

type frameWriterFactory struct {
	*bufio.Writer

	needMaskingKey bool
}

func (buf frameWriterFactory) NewFrameWriter(payloadType byte) *frameWriter {
	frameHeader := &frameHeader{Fin: true, OpCode: payloadType}
	if buf.needMaskingKey {
		frameHeader.MaskingKey = make([]byte, 4)
		io.ReadFull(rand.Reader, frameHeader.MaskingKey)
	}
	return &frameWriter{writer: buf.Writer, header: frameHeader}
}

type frameHandler struct {
	conn        *Conn
	payloadType byte
}

func (handler *frameHandler) HandleFrame(frame *frameReader) (*frameReader, error) {
	if handler.conn.IsServerConn() {
		// The client MUST mask all frames sent to the server.
		if frame.header.MaskingKey == nil {
			handler.WriteClose(closeStatusProtocolError)
			return nil, io.EOF
		}
	} else {
		// The server MUST NOT mask all frames.
		if frame.header.MaskingKey != nil {
			handler.WriteClose(closeStatusProtocolError)
			return nil, io.EOF
		}
	}
	if header := frame.HeaderReader(); header != nil {
		io.Copy(io.Discard, header)
	}
	switch frame.PayloadType() {
	case ContinuationFrame:
		frame.header.OpCode = handler.payloadType
	case TextFrame, BinaryFrame:
		handler.payloadType = frame.PayloadType()
	case CloseFrame:
		return nil, io.EOF
	case PingFrame, PongFrame:
		b := make([]byte, maxControlFramePayloadLength)
		n, err := io.ReadFull(frame, b)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, err
		}
		io.Copy(io.Discard, frame)
		if frame.PayloadType() == PingFrame {
			if _, err := handler.WritePong(b[:n]); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	return frame, nil
}

func (handler *frameHandler) WriteClose(status int) error {
	handler.conn.wio.Lock()
	defer handler.conn.wio.Unlock()
	w := handler.conn.frameWriterFactory.NewFrameWriter(CloseFrame)
	defer w.Close()
	msg := make([]byte, 2)
	binary.BigEndian.PutUint16(msg, uint16(status))
	_, err := w.Write(msg)
	return err
}

func (handler *frameHandler) WritePing(msg []byte) (int, error) {
	handler.conn.wio.Lock()
	defer handler.conn.wio.Unlock()
	w := handler.conn.frameWriterFactory.NewFrameWriter(PingFrame)
	defer w.Close()
	return w.Write(msg)
}

func (handler *frameHandler) WritePong(msg []byte) (int, error) {
	handler.conn.wio.Lock()
	defer handler.conn.wio.Unlock()
	w := handler.conn.frameWriterFactory.NewFrameWriter(PongFrame)
	defer w.Close()
	return w.Write(msg)
}

// newConn creates a new WebSocket connection.
func newConn(config *Config, buf *bufio.ReadWriter, rwc io.ReadWriteCloser, request *http.Request) *Conn {
	if buf == nil {
		br := bufio.NewReader(rwc)
		bw := bufio.NewWriter(rwc)
		buf = bufio.NewReadWriter(br, bw)
	}
	ws := &Conn{config: config, request: request, buf: buf, rwc: rwc,
		frameReaderFactory: frameReaderFactory{buf.Reader},
		frameWriterFactory: frameWriterFactory{
			buf.Writer, request == nil},
		PayloadType: TextFrame,
	}
	ws.frameHandler = &frameHandler{conn: ws}
	return ws
}

// generateNonce generates a nonce consisting of a randomly selected 16-byte
// value that has been base64-encoded.
func generateNonce() []byte {
	key := make([]byte, 16)
	io.ReadFull(rand.Reader, key)
	nonce := make([]byte, 24)
	base64.StdEncoding.Encode(nonce, key)
	return nonce
}

// removeZone removes IPv6 zone identifier from host.
// E.g., "[fe80::1%en0]:8080" to "[fe80::1]:8080"
func removeZone(host string) string {
	if !strings.HasPrefix(host, "[") {
		return host
	}
	i := strings.LastIndex(host, "]")
	if i < 0 {
		return host
	}
	j := strings.LastIndex(host[:i], "%")
	if j < 0 {
		return host
	}
	return host[:j] + host[i:]
}

// getNonceAccept computes the base64-encoded SHA-1 of the concatenation of
// the nonce ("Sec-WebSocket-Key" value) with the websocket GUID string.
func getNonceAccept(nonce []byte) []byte {
	h := sha1.New()
	h.Write(nonce)
	h.Write([]byte(websocketGUID))
	expected := make([]byte, 28)
	base64.StdEncoding.Encode(expected, h.Sum(nil))
	return expected
}

func clientHandshake(config *Config, br *bufio.Reader, bw *bufio.Writer) error {
	bw.WriteString("GET " + config.Location.RequestURI() + " HTTP/1.1\r\n")

	// According to RFC 6874, an HTTP client, proxy, or other
	// intermediary must remove any IPv6 zone identifier attached
	// to an outgoing URI.
	bw.WriteString("Host: " + removeZone(config.Location.Host) + "\r\n")
	bw.WriteString("Upgrade: websocket\r\n")
	bw.WriteString("Connection: Upgrade\r\n")
	nonce := generateNonce()
	if config.handshakeData != nil {
		nonce = []byte(config.handshakeData["key"])
	}
	bw.WriteString("Sec-WebSocket-Key: " + string(nonce) + "\r\n")
	bw.WriteString("Origin: " + strings.ToLower(config.Origin.String()) + "\r\n")

	if config.Version != ProtocolVersionHybi13 {
		return ErrBadProtocolVersion
	}

	bw.WriteString("Sec-WebSocket-Version: " + fmt.Sprintf("%d", config.Version) + "\r\n")
	if len(config.Protocol) > 0 {
		bw.WriteString("Sec-WebSocket-Protocol: " + strings.Join(config.Protocol, ", ") + "\r\n")
	}
	// TODO(ukai): send Sec-WebSocket-Extensions.
	if err := config.Header.WriteSubset(bw, handshakeHeader); err != nil {
		return err
	}

	bw.WriteString("\r\n")
	if err := bw.Flush(); err != nil {
		return err
	}

	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return ErrBadStatus
	}
	if strings.ToLower(resp.Header.Get("Upgrade")) != "websocket" ||
		strings.ToLower(resp.Header.Get("Connection")) != "upgrade" {
		return ErrBadUpgrade
	}
	expectedAccept := getNonceAccept(nonce)
	if resp.Header.Get("Sec-WebSocket-Accept") != string(expectedAccept) {
		return ErrChallengeResponse
	}
	if resp.Header.Get("Sec-WebSocket-Extensions") != "" {
		return ErrUnsupportedExtensions
	}
	offeredProtocol := resp.Header.Get("Sec-WebSocket-Protocol")
	if offeredProtocol != "" {
		protocolMatched := false
		for i := range len(config.Protocol) {
			if config.Protocol[i] == offeredProtocol {
				protocolMatched = true
				break
			}
		}
		if !protocolMatched {
			return ErrBadWebSocketProtocol
		}
		config.Protocol = []string{offeredProtocol}
	}

	return nil
}

// newClientConn creates a client WebSocket connection after handshake.
func newClientConn(config *Config, buf *bufio.ReadWriter, rwc io.ReadWriteCloser) *Conn {
	return newConn(config, buf, rwc, nil)
}

// A serverHandshaker performs a server handshake.
type serverHandshaker struct {
	*Config

	accept []byte
}

// ReadHandshake reads handshake request message from client.
// Returns http response code and error if any.
func (c *serverHandshaker) ReadHandshake(req *http.Request) (int, error) {
	c.Version = ProtocolVersionHybi13
	if req.Method != http.MethodGet {
		return http.StatusMethodNotAllowed, ErrBadRequestMethod
	}
	// HTTP version can be safely ignored.

	if strings.ToLower(req.Header.Get("Upgrade")) != "websocket" ||
		!strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		return http.StatusBadRequest, ErrNotWebSocket
	}

	key := req.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return http.StatusBadRequest, ErrChallengeResponse
	}
	version := req.Header.Get("Sec-WebSocket-Version")
	switch version {
	case "13":
		c.Version = ProtocolVersionHybi13
	default:
		return http.StatusBadRequest, ErrBadWebSocketVersion
	}
	var scheme string
	if req.TLS != nil {
		scheme = "wss"
	} else {
		scheme = "ws"
	}
	var err error
	c.Location, err = url.ParseRequestURI(scheme + "://" + req.Host + req.URL.RequestURI())
	if err != nil {
		return http.StatusBadRequest, err
	}
	protocol := strings.TrimSpace(req.Header.Get("Sec-WebSocket-Protocol"))
	if protocol != "" {
		for p := range strings.SplitSeq(protocol, ",") {
			c.Protocol = append(c.Protocol, strings.TrimSpace(p))
		}
	}
	c.accept = getNonceAccept([]byte(key))
	return http.StatusSwitchingProtocols, nil
}

// Origin parses the Origin header in req.
// If the Origin header is not set, it returns nil and nil.
func Origin(config *Config, req *http.Request) (*url.URL, error) {
	var origin string
	switch config.Version {
	case ProtocolVersionHybi13:
		origin = req.Header.Get("Origin")
	}
	if origin == "" {
		return nil, nil
	}
	return url.ParseRequestURI(origin)
}

// AcceptHandshake accepts the client handshake request and sends
// handshake response back to client.
func (c *serverHandshaker) AcceptHandshake(buf *bufio.Writer) error {
	if len(c.Protocol) > 0 {
		if len(c.Protocol) != 1 {
			// You need choose a Protocol in Handshake func in Server.
			return ErrBadWebSocketProtocol
		}
	}
	buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	buf.WriteString("Upgrade: websocket\r\n")
	buf.WriteString("Connection: Upgrade\r\n")
	buf.WriteString("Sec-WebSocket-Accept: " + string(c.accept) + "\r\n")
	if len(c.Protocol) > 0 {
		buf.WriteString("Sec-WebSocket-Protocol: " + c.Protocol[0] + "\r\n")
	}
	// TODO(ukai): send Sec-WebSocket-Extensions.
	if c.Header != nil {
		if err := c.Header.WriteSubset(buf, handshakeHeader); err != nil {
			return err
		}
	}
	buf.WriteString("\r\n")
	return buf.Flush()
}

// NewServerConn creates a new WebSocket connection.
func (c *serverHandshaker) NewServerConn(buf *bufio.ReadWriter, rwc io.ReadWriteCloser, request *http.Request) *Conn {
	return newConn(c.Config, buf, rwc, request)
}
