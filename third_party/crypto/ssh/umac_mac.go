package ssh

// UMAC support, added in this fork. Not present upstream.
//
// See ssh/internal/umac for the algorithm and its RFC 4418 validation. This
// file is only the adapter that lets it satisfy the hash.Hash shape the
// transport expects.

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"

	"golang.org/x/crypto/ssh/internal/umac"
)

// umacKeyLen is the key length OpenSSH derives for the umac modes: 16 bytes,
// which UMAC uses as an AES-128 key.
const umacKeyLen = 16

// umacHash adapts UMAC to hash.Hash so it can sit in macModes alongside the
// HMAC constructions.
//
// The shapes do not quite line up. UMAC is nonce-based: each packet is
// authenticated under the sequence number, which is what makes it safe to reuse
// one key across a session. hash.Hash has nowhere to put a nonce.
//
// The transport resolves it by accident of layout. For every packet it calls
// Reset, writes the four-byte big-endian sequence number, and then writes the
// packet body -- so the nonce always arrives first and is always exactly four
// bytes. This type consumes those four bytes as the nonce and treats the
// remainder as the message.
//
// That coupling to the caller's write order is worth stating plainly: it is
// correct for this transport and would silently produce wrong tags for any
// caller that wrote the body first. It is unexported and used in exactly one
// place for that reason.
type umacHash struct {
	u       *umac.UMAC
	tagLen  int
	nonce   [8]byte
	haveSeq int // bytes of the sequence number consumed so far
	msg     []byte
}

func newUMACHash(key []byte, tagLen int) hash.Hash {
	u, err := umac.New(key[:umacKeyLen], tagLen)
	if err != nil {
		// Unreachable: the key length is fixed by macModes and the tag length
		// by the four call sites below.
		panic("ssh: umac: " + err.Error())
	}
	return &umacHash{u: u, tagLen: tagLen}
}

func (h *umacHash) Reset() {
	h.haveSeq = 0
	h.msg = h.msg[:0]
	for i := range h.nonce {
		h.nonce[i] = 0
	}
}

// Write takes the first four bytes as the packet sequence number and everything
// after as the message.
//
// The sequence number is placed in the low four bytes of the eight-byte nonce,
// which is how OpenSSH forms it: the nonce is the 64-bit sequence number in big
// endian, and SSH's counter is 32 bits, so the high half is always zero.
func (h *umacHash) Write(p []byte) (int, error) {
	n := len(p)

	if h.haveSeq < 4 {
		take := 4 - h.haveSeq
		if take > len(p) {
			take = len(p)
		}
		copy(h.nonce[4+h.haveSeq:], p[:take])
		h.haveSeq += take
		p = p[take:]
	}

	h.msg = append(h.msg, p...)
	return n, nil
}

func (h *umacHash) Sum(in []byte) []byte {
	return append(in, h.u.Tag(h.nonce[:], h.msg)...)
}

func (h *umacHash) Size() int { return h.tagLen }

// BlockSize has no meaning for UMAC, which is not a Merkle-Damgard hash. The
// transport never consults it; AES's block size is reported as the least
// misleading answer.
func (h *umacHash) BlockSize() int { return 16 }

func init() {
	macModes[UMAC64ETM] = &macMode{umacKeyLen, true, func(key []byte) hash.Hash {
		return newUMACHash(key, 8)
	}}
	macModes[UMAC128ETM] = &macMode{umacKeyLen, true, func(key []byte) hash.Hash {
		return newUMACHash(key, 16)
	}}
	macModes[UMAC64] = &macMode{umacKeyLen, false, func(key []byte) hash.Hash {
		return newUMACHash(key, 8)
	}}
	macModes[UMAC128] = &macMode{umacKeyLen, false, func(key []byte) hash.Hash {
		return newUMACHash(key, 16)
	}}

	// Not UMAC, but the same motivation: upstream ships plain hmac-sha1 and
	// omits the encrypt-then-MAC form, and OpenSSH offers both.
	macModes[HMACSHA1ETM] = &macMode{20, true, func(key []byte) hash.Hash {
		return hmac.New(sha1.New, key)
	}}
}
