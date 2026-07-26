package rdp

import (
	"encoding/binary"
	"strings"
)

// connectionRequest holds the fields recovered from an X.224 Connection
// Request PDU (MS-RDPBCGR 2.2.1.1).
type connectionRequest struct {
	Cookie       string
	RoutingToken string
	Protocols    uint32
}

// RDP Negotiation Request security protocol flags (MS-RDPBCGR 2.2.1.1.1).
const (
	protoRDP       = 0x00000000
	protoSSL       = 0x00000001
	protoHybrid    = 0x00000002
	protoRDSTLS    = 0x00000004
	protoHybridEx  = 0x00000008
)

// parseConnectionRequest recovers the cookie, routing token, and requested
// security protocols from a client's first PDU.
//
// Wire shape:
//
//	TPKT header        4 bytes  (version, reserved, length[2])
//	X.224 CR header    varies   (length indicator, 0xE0, dst-ref[2], src-ref[2], class)
//	optional token     "Cookie: mstshash=<value>\r\n"  or  routing token
//	optional RDP Neg Request  8 bytes (type=0x01, flags, length[2], requestedProtocols[4])
//
// It is written to tolerate truncation and junk: scanners send malformed and
// partial PDUs constantly, and a parser that rejected them would discard the
// very cookies worth capturing.
func parseConnectionRequest(data []byte) connectionRequest {
	var cr connectionRequest
	if len(data) < 11 {
		return cr
	}

	// Skip the 4-byte TPKT header if present (version byte is 0x03).
	body := data
	if data[0] == 0x03 {
		if len(data) < 4 {
			return cr
		}
		body = data[4:]
	}

	// body now begins at the X.224 length indicator. The fixed part is 7 bytes
	// in total: LI(1), code(1), dst-ref(2), src-ref(2), class(1). The LI value
	// itself counts only the bytes that follow it, which is the easy place to
	// go wrong by one.
	const x224FixedLen = 7
	if len(body) < x224FixedLen {
		return cr
	}
	variable := body[x224FixedLen:]

	// The variable part is a single line terminated by CRLF, either a cookie
	// or a routing token, optionally followed by the negotiation request.
	if idx := indexCRLF(variable); idx >= 0 {
		line := string(variable[:idx])
		switch {
		case strings.HasPrefix(line, "Cookie: mstshash="):
			cr.Cookie = sanitize(strings.TrimPrefix(line, "Cookie: mstshash="))
		case strings.HasPrefix(line, "Cookie:"):
			cr.Cookie = sanitize(strings.TrimSpace(strings.TrimPrefix(line, "Cookie:")))
		case len(line) > 0 && line[0] == 0x03:
			// Routing token form (rare); recorded raw.
			cr.RoutingToken = sanitize(line)
		}
		// The negotiation request, if any, follows the CRLF.
		rest := variable[idx+2:]
		cr.Protocols = parseNegRequest(rest)
	} else {
		// No CRLF: the whole variable part may be a bare negotiation request.
		cr.Protocols = parseNegRequest(variable)
	}

	return cr
}

// parseNegRequest reads the 8-byte RDP Negotiation Request, returning the
// requested-protocols bitmask. Type byte 0x01 identifies the structure.
func parseNegRequest(data []byte) uint32 {
	if len(data) >= 8 && data[0] == 0x01 {
		return binary.LittleEndian.Uint32(data[4:8])
	}
	return protoRDP
}

// protocolNames renders the requested-protocols bitmask.
//
// The pattern is a fingerprint: a client demanding Hybrid (NLA) behaves
// differently from a scanner probing bare RDP security, and the combination
// distinguishes tools.
func (cr connectionRequest) protocolNames() []string {
	if cr.Protocols == protoRDP {
		return []string{"RDP"}
	}
	var names []string
	if cr.Protocols&protoSSL != 0 {
		names = append(names, "SSL")
	}
	if cr.Protocols&protoHybrid != 0 {
		names = append(names, "HYBRID")
	}
	if cr.Protocols&protoRDSTLS != 0 {
		names = append(names, "RDSTLS")
	}
	if cr.Protocols&protoHybridEx != 0 {
		names = append(names, "HYBRID_EX")
	}
	if len(names) == 0 {
		return []string{"RDP"}
	}
	return names
}

// clientInfo holds fields recovered from a later PDU.
type clientInfo struct {
	ClientName string
	Build      string
}

// parseClientInfo makes a best-effort scan of an MCS Connect Initial for the
// client name, which the Client Core Data carries as a UTF-16LE field. This is
// heuristic: fully parsing GCC/MCS is disproportionate for one string, so the
// parser looks for the clientName field's characteristic run of UTF-16LE
// printable characters.
func parseClientInfo(data []byte) clientInfo {
	var info clientInfo

	// The Client Core Data header type is 0xC001 (CS_CORE), little-endian.
	for i := 0; i+2 < len(data); i++ {
		if data[i] == 0x01 && data[i+1] == 0xC0 {
			// clientName sits at a fixed offset (version[4], desktopWidth[2],
			// desktopHeight[2], colorDepth[2], sasSequence[2], keyboardLayout[4],
			// clientBuild[4]) = 20 bytes into the core data body, which starts
			// 4 bytes after the header type+length.
			base := i + 2 + 2
			if build := base + 16; build+4 <= len(data) {
				b := binary.LittleEndian.Uint32(data[build : build+4])
				if b > 0 && b < 100000 {
					info.Build = itoa(int(b))
				}
			}
			if name := base + 20; name+32 <= len(data) {
				info.ClientName = utf16le(data[name : name+32])
			}
			break
		}
	}
	return info
}

// ---- helpers ----

func indexCRLF(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}

// sanitize strips control characters from a captured string so a hostile
// cookie cannot smuggle terminal escapes into logs.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 256 {
		out = out[:256]
	}
	return out
}

func utf16le(b []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(byte(c))
		}
	}
	return strings.TrimSpace(sb.String())
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// negotiationResponse builds an X.224 Connection Confirm carrying an RDP
// Negotiation Response that selects standard RDP security (protocol 0). TPKT +
// X.224 CC + 8-byte neg response.
func negotiationResponse() []byte {
	neg := []byte{
		0x02,       // type: TYPE_RDP_NEG_RSP
		0x00,       // flags
		0x08, 0x00, // length (8)
		byte(protoRDP), 0x00, 0x00, 0x00, // selectedProtocol
	}

	// X.224 Connection Confirm: LI, 0xD0, dst-ref[2], src-ref[2], class.
	x224 := append([]byte{
		byte(6 + len(neg)), // length indicator
		0xD0,               // CC-TPDU
		0x00, 0x00,         // dst-ref
		0x12, 0x34,         // src-ref
		0x00,               // class
	}, neg...)

	total := 4 + len(x224)
	tpkt := []byte{0x03, 0x00, byte(total >> 8), byte(total & 0xff)}
	return append(tpkt, x224...)
}
