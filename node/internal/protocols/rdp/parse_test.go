package rdp

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildCR assembles an X.224 Connection Request the way a real client does, so
// the parser is tested against wire-shaped input rather than a convenient
// fiction.
func buildCR(cookie string, protocols uint32, withNeg bool) []byte {
	var variable []byte
	if cookie != "" {
		variable = append(variable, []byte("Cookie: mstshash="+cookie+"\r\n")...)
	}
	if withNeg {
		neg := make([]byte, 8)
		neg[0] = 0x01 // TYPE_RDP_NEG_REQ
		neg[1] = 0x00
		binary.LittleEndian.PutUint16(neg[2:4], 8)
		binary.LittleEndian.PutUint32(neg[4:8], protocols)
		variable = append(variable, neg...)
	}

	x224 := append([]byte{
		byte(6 + len(variable)), // length indicator
		0xE0,                    // CR-TPDU
		0x00, 0x00,              // dst-ref
		0x00, 0x00,              // src-ref
		0x00,                    // class
	}, variable...)

	total := 4 + len(x224)
	tpkt := []byte{0x03, 0x00, byte(total >> 8), byte(total & 0xff)}
	return append(tpkt, x224...)
}

func TestParseConnectionRequestExtractsCookie(t *testing.T) {
	// The mstshash cookie routinely carries the attacker's own hostname or the
	// username baked into their tooling, which is why it is worth parsing at
	// all when the handshake is never completed.
	cases := []struct{ cookie string }{
		{"ADMINISTRATOR"},
		{"hydra"},
		{"DESKTOP-4F9K2L1"},
		{"user"},
	}
	for _, tc := range cases {
		cr := parseConnectionRequest(buildCR(tc.cookie, protoHybrid, true))
		if cr.Cookie != tc.cookie {
			t.Errorf("cookie = %q, want %q", cr.Cookie, tc.cookie)
		}
	}
}

func TestParseConnectionRequestReadsRequestedProtocols(t *testing.T) {
	// The requested-protocol pattern fingerprints the tool: a client demanding
	// NLA behaves differently from one probing bare RDP security.
	cases := []struct {
		protocols uint32
		want      []string
	}{
		{protoRDP, []string{"RDP"}},
		{protoSSL, []string{"SSL"}},
		{protoSSL | protoHybrid, []string{"SSL", "HYBRID"}},
		{protoSSL | protoHybrid | protoHybridEx, []string{"SSL", "HYBRID", "HYBRID_EX"}},
	}
	for _, tc := range cases {
		cr := parseConnectionRequest(buildCR("x", tc.protocols, true))
		got := cr.protocolNames()
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("protocols 0x%x = %v, want %v", tc.protocols, got, tc.want)
		}
	}
}

func TestParseConnectionRequestToleratesMalformedInput(t *testing.T) {
	// Scanners send truncated and junk PDUs constantly. A parser that panicked
	// or rejected them would take the listener down or discard the cookies
	// worth capturing.
	inputs := [][]byte{
		nil,
		{},
		{0x03},
		{0x03, 0x00, 0x00},
		{0x03, 0x00, 0x00, 0x2c, 0xff},
		[]byte("garbage that is not a PDU at all"),
		append(buildCR("trunc", protoHybrid, true)[:9]),
		{0x03, 0x00, 0xff, 0xff, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input %d panicked: %v", i, r)
				}
			}()
			_ = parseConnectionRequest(in)
		}()
	}
}

func TestParseConnectionRequestHandlesNoCookie(t *testing.T) {
	// Many scanners send a bare negotiation request with no cookie at all.
	cr := parseConnectionRequest(buildCR("", protoSSL|protoHybrid, true))
	if cr.Cookie != "" {
		t.Errorf("cookie = %q, want empty", cr.Cookie)
	}
	if got := cr.protocolNames(); strings.Join(got, ",") != "SSL,HYBRID" {
		t.Errorf("protocols = %v, want [SSL HYBRID]", got)
	}
}

func TestCookieIsSanitized(t *testing.T) {
	// A hostile cookie must not smuggle terminal escapes into operator logs.
	raw := buildCR("evil\x1b[31mred\x00\x07", protoRDP, false)
	cr := parseConnectionRequest(raw)
	if strings.ContainsAny(cr.Cookie, "\x1b\x00\x07") {
		t.Errorf("cookie %q still contains control characters", cr.Cookie)
	}
	if !strings.Contains(cr.Cookie, "evil") {
		t.Errorf("sanitizing removed the payload entirely: %q", cr.Cookie)
	}
}

func TestCookieIsLengthBounded(t *testing.T) {
	cr := parseConnectionRequest(buildCR(strings.Repeat("A", 4096), protoRDP, false))
	if len(cr.Cookie) > 256 {
		t.Errorf("cookie length = %d, want <= 256", len(cr.Cookie))
	}
}

func TestNegotiationResponseIsWellFormed(t *testing.T) {
	resp := negotiationResponse()

	if len(resp) < 11 {
		t.Fatalf("response is %d bytes, too short for TPKT + X.224 CC", len(resp))
	}
	if resp[0] != 0x03 {
		t.Errorf("TPKT version = 0x%02x, want 0x03", resp[0])
	}
	declared := int(binary.BigEndian.Uint16(resp[2:4]))
	if declared != len(resp) {
		t.Errorf("TPKT declares %d bytes, actual length %d", declared, len(resp))
	}
	if resp[5] != 0xD0 {
		t.Errorf("X.224 code = 0x%02x, want 0xD0 (CC-TPDU)", resp[5])
	}
	if resp[11] != 0x02 {
		t.Errorf("neg response type = 0x%02x, want 0x02 (TYPE_RDP_NEG_RSP)", resp[11])
	}
}
