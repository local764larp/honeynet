package umac

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// The RFC 4418 verification vectors, all under key "abcdefghijklmnop" and
// nonce "bcdefghi".
//
// These are the whole basis for trusting this package. The specification leaves
// several details ambiguous in prose -- how a short block is padded, which end
// of the AES output a short tag comes from, the word endianness inside NH --
// and each one was settled by running these rather than by picking the reading
// that looked right. An implementation that reproduces all of them agrees with
// the reference on empty input, sub-block input, exact block multiples, and the
// long inputs that exercise the polynomial ramp.
const (
	vectorKey   = "abcdefghijklmnop"
	vectorNonce = "bcdefghi"
)

type vector struct {
	name   string
	msg    []byte
	umac64 string
	umac96 string

	// needsRamp marks the one vector that crosses into the 128-bit prime.
	// That construction is not implemented -- see l2Hash -- so the vector is
	// kept here as the record of what is missing rather than deleted, and the
	// tests assert that such a message is rejected instead of mis-tagged.
	needsRamp bool
}

func vectors() []vector {
	rep := func(s string, n int) []byte { return bytes.Repeat([]byte(s), n) }

	return []vector{
		{name: "empty", msg: nil, umac64: "6E155FAD26900BE1", umac96: "32FEDB100C79AD58F07FF764"},
		{name: "a3", msg: rep("a", 3), umac64: "44B5CB542F220104", umac96: "185E4FE905CBA7BD85E4C2DC"},
		{name: "a2^10", msg: rep("a", 1 << 10), umac64: "26BF2F5D60118BD9", umac96: "7A54ABE04AF82D60FB298C3C"},
		{name: "a2^15", msg: rep("a", 1 << 15), umac64: "27F8EF643B0D118D", umac96: "7B136BD911E4B734286EF2BE"},
		{name: "a2^20", msg: rep("a", 1 << 20), umac64: "A4477E87E9F55853", umac96: "F8ACFA3AC31CFEEA047F7B11"},
		{name: "a2^25", msg: rep("a", 1 << 25), umac64: "2E2DBC36860A0A5F", umac96: "72C6388BACE3ACE6FBF062D9", needsRamp: true},
		{name: "abc1", msg: rep("abc", 1), umac64: "D4D7B9F6BD4FBFCF", umac96: "883C3D4B97A61976FFCF2323"},
		{name: "abc500", msg: rep("abc", 500), umac64: "D4CF26DDEFD5C01A", umac96: "8824A260C53C66A36C9260A6"},
	}
}

// A message past the validated boundary must be refused, not tagged. Returning
// a tag computed without the polynomial ramp would be silently wrong, and a
// MAC that silently disagrees with the peer is worse than one that is absent.
func TestOversizedMessageIsRejected(t *testing.T) {
	u, err := New([]byte(vectorKey), 8)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Error("tagging a message past MaxMessageLen returned instead of panicking")
		}
	}()
	u.Tag([]byte(vectorNonce), bytes.Repeat([]byte("a"), MaxMessageLen+1))
}

// SSH cannot reach the unimplemented path. RFC 4253 caps a packet at 256 KiB
// and OpenSSH negotiates 32 KiB; both are far below the boundary.
func TestSSHPacketSizesAreWithinTheValidatedRange(t *testing.T) {
	const rfc4253MaxPacket = 256 << 10
	if rfc4253MaxPacket >= MaxMessageLen {
		t.Fatalf("MaxMessageLen (%d) does not cover the largest SSH packet (%d)",
			MaxMessageLen, rfc4253MaxPacket)
	}
}

func tagHex(t *testing.T, tagLen int, msg []byte) string {
	t.Helper()

	u, err := New([]byte(vectorKey), tagLen)
	if err != nil {
		t.Fatalf("New(tagLen=%d): %v", tagLen, err)
	}
	return strings.ToUpper(hex.EncodeToString(u.Tag([]byte(vectorNonce), msg)))
}

// UMAC-64 is umac-64@openssh.com. Two iterations.
func TestRFC4418VectorsUMAC64(t *testing.T) {
	for _, v := range vectors() {
		if v.needsRamp {
			continue
		}
		t.Run(v.name, func(t *testing.T) {
			if got := tagHex(t, 8, v.msg); got != v.umac64 {
				t.Errorf("UMAC-64(%s)\n  got  %s\n  want %s", v.name, got, v.umac64)
			}
		})
	}
}

// UMAC-96 is not used by SSH, but it runs three iterations where UMAC-64 runs
// two. Passing it is what shows the Toeplitz key shift and the per-iteration
// key slicing are right at a count other than the one the 64-bit case happens
// to exercise.
func TestRFC4418VectorsUMAC96(t *testing.T) {
	for _, v := range vectors() {
		if v.needsRamp {
			continue
		}
		t.Run(v.name, func(t *testing.T) {
			if got := tagHex(t, 12, v.msg); got != v.umac96 {
				t.Errorf("UMAC-96(%s)\n  got  %s\n  want %s", v.name, got, v.umac96)
			}
		})
	}
}

// UMAC-128 is umac-128@openssh.com. No published vector is embedded here, so
// this asserts only the shape and the properties any MAC must have; the
// correctness argument for it rests on the 64- and 96-bit vectors passing,
// since the layers are identical and only the iteration count differs.
func TestUMAC128Shape(t *testing.T) {
	u, err := New([]byte(vectorKey), 16)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tag := u.Tag([]byte(vectorNonce), []byte("message"))
	if len(tag) != 16 {
		t.Fatalf("tag length = %d, want 16", len(tag))
	}
	if bytes.Equal(tag, make([]byte, 16)) {
		t.Error("tag is all zeroes")
	}
}

func TestTagVariesWithNonce(t *testing.T) {
	u, err := New([]byte(vectorKey), 8)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	msg := []byte("the same message")
	a := u.Tag([]byte("bcdefghi"), msg)
	b := u.Tag([]byte("bcdefghj"), msg)
	if bytes.Equal(a, b) {
		t.Error("two nonces produced the same tag")
	}
}

// The low nonce bit selects which half of one AES block the pad comes from, so
// nonces differing only in that bit share an encryption. They must still
// produce different tags.
func TestAdjacentNoncesDiffer(t *testing.T) {
	u, err := New([]byte(vectorKey), 8)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	msg := []byte("packet")
	even := u.Tag([]byte("bcdefgh\x00"), msg)
	odd := u.Tag([]byte("bcdefgh\x01"), msg)
	if bytes.Equal(even, odd) {
		t.Error("nonces differing only in the low bit produced the same tag")
	}
}

func TestTagIsDeterministic(t *testing.T) {
	u, err := New([]byte(vectorKey), 8)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	msg := []byte("repeatable")
	first := u.Tag([]byte(vectorNonce), msg)
	for i := 0; i < 100; i++ {
		if got := u.Tag([]byte(vectorNonce), msg); !bytes.Equal(got, first) {
			t.Fatalf("tag changed on call %d", i)
		}
	}
}

func TestRejectsUnsupportedTagLengths(t *testing.T) {
	for _, n := range []int{0, 1, 5, 7, 9, 15, 17, 32, -8} {
		if _, err := New([]byte(vectorKey), n); err == nil {
			t.Errorf("New(tagLen=%d) succeeded; want an error", n)
		}
	}
}
