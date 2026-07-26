package sshd

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"sync"
)

// sniffConn tees the first bytes a client sends so the algorithm lists in its
// SSH_MSG_KEXINIT can be recovered.
//
// This exists because x/crypto/ssh gives a server no access to the client's
// KEXINIT, and that message is the source of the HASSH fingerprint -- the most
// reliable client-library identifier available, since unlike the version banner
// it is not a string the client picks. Reading it means teeing the raw
// connection before the handshake consumes it.
//
// Only the pre-encryption prefix is captured. Once the limit is reached the tee
// switches off and the wrapper becomes a plain pass-through.
type sniffConn struct {
	net.Conn
	mu   sync.Mutex
	buf  bytes.Buffer
	full bool

	// onClose fires exactly once when the underlying connection is torn down.
	// This is the only reliable signal for "the attacker's session is over":
	// an SSH connection carries many channels, and a scripted loader opens a
	// fresh channel per command, so channel teardown says nothing about the
	// session as a whole.
	closeOnce sync.Once
	onClose   func()
}

// sniffLimit is comfortably larger than a version line plus a KEXINIT packet
// while staying small enough that a client which never sends one costs nothing.
const sniffLimit = 16 << 10

func newSniffConn(c net.Conn, onClose func()) *sniffConn {
	return &sniffConn{Conn: c, onClose: onClose}
}

// Close tears down the connection and fires the session-end hook once.
func (c *sniffConn) Close() error {
	err := c.Conn.Close()
	if c.onClose != nil {
		c.closeOnce.Do(c.onClose)
	}
	return err
}

func (c *sniffConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if !c.full {
			c.buf.Write(p[:n])
			if c.buf.Len() >= sniffLimit {
				c.full = true
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *sniffConn) captured() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

// clientHello is what the sniffer recovers from the handshake prefix.
type clientHello struct {
	Banner      string
	Kex         []string
	HostKeyAlgs []string
	Ciphers     []string
	MACs        []string
	Compression []string
	Parsed      bool
}

// parseHello extracts the version banner and the client-to-server algorithm
// lists from a captured handshake prefix.
//
// Wire format, all big-endian:
//
//	"SSH-2.0-<software>\r\n"
//	uint32 packet_length
//	byte   padding_length
//	byte   message_type   (20 == SSH_MSG_KEXINIT)
//	byte[16] cookie
//	name-list x10
//	...
//
// A name-list is a uint32 byte count followed by comma-separated ASCII.
func parseHello(buf []byte) clientHello {
	var h clientHello

	// Clients may send comment lines before the version string. RFC 4253
	// allows it and some scanners do it.
	rest := buf
	for {
		idx := bytes.Index(rest, []byte("\r\n"))
		if idx < 0 {
			return h
		}
		line := string(rest[:idx])
		rest = rest[idx+2:]
		if strings.HasPrefix(line, "SSH-") {
			h.Banner = line
			break
		}
		if len(rest) == 0 {
			return h
		}
	}

	if len(rest) < 6 {
		return h
	}
	packetLen := binary.BigEndian.Uint32(rest[0:4])
	padLen := int(rest[4])
	if packetLen < 2 || int(packetLen) > len(rest)-4 {
		return h
	}
	payloadLen := int(packetLen) - padLen - 1
	if payloadLen <= 0 || 5+payloadLen > len(rest) {
		return h
	}
	payload := rest[5 : 5+payloadLen]

	const msgKexInit = 20
	if len(payload) < 17 || payload[0] != msgKexInit {
		return h
	}
	p := payload[17:] // skip message type + 16-byte cookie

	lists := make([][]string, 0, 10)
	for i := 0; i < 10; i++ {
		if len(p) < 4 {
			return h
		}
		n := binary.BigEndian.Uint32(p[0:4])
		if int(n) > len(p)-4 {
			return h
		}
		raw := string(p[4 : 4+n])
		p = p[4+n:]

		var items []string
		if raw != "" {
			items = strings.Split(raw, ",")
		}
		lists = append(lists, items)
	}

	h.Kex = lists[0]
	h.HostKeyAlgs = lists[1]
	h.Ciphers = lists[2]     // encryption_algorithms_client_to_server
	h.MACs = lists[4]        // mac_algorithms_client_to_server
	h.Compression = lists[6] // compression_algorithms_client_to_server
	h.Parsed = true
	return h
}
