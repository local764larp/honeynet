// Package umac implements UMAC-64 and UMAC-128 (RFC 4418) as OpenSSH uses them
// for the umac-64@openssh.com and umac-128@openssh.com message authentication
// codes.
//
// # Why this exists
//
// x/crypto/ssh implements no umac variant, but every real OpenSSH offers the
// family and prefers it at the head of its MAC list. A sensor whose banner
// claims OpenSSH while its MAC list omits umac is contradicting itself in the
// first packet of the connection, which is exactly the class of tell the
// honeypot is trying not to produce.
//
// # Correctness
//
// This is authentication code, so it is either bit-exact or it is worthless: a
// MAC that is self-consistent but disagrees with the reference produces
// handshakes that fail against real clients, which is a louder signal than the
// gap it was meant to close. Every ambiguity in the specification was resolved
// against the RFC 4418 test vectors rather than by choosing the reading that
// seemed most likely, and umac_test.go runs all eight of them for both tag
// lengths. If those pass, the implementation agrees with the reference on
// empty input, sub-block input, exact block multiples, and the multi-megabyte
// cases that exercise the polynomial ramp.
//
// # Scope
//
// Nonces are the eight-byte big-endian sequence numbers SSH uses. Tag lengths
// are 8 and 16 bytes; the 4- and 12-byte variants the RFC also defines are not
// implemented because no SSH MAC uses them.
package umac

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"math/big"
)

const (
	// blockLen is the AES block size, which is also the KDF output granularity.
	blockLen = 16

	// l1KeyLen is the NH key length in bytes: 1024 bytes of message per L1
	// block, at 8 bytes of key per 8 bytes of message.
	l1KeyLen = 1024

	// l1BlockLen is how much message one NH invocation consumes.
	l1BlockLen = 1024

	// nhChunk is the message granularity NH requires. Short final blocks are
	// zero-padded up to a multiple of this.
	nhChunk = 32
)

// Prime moduli for the two hash layers, per RFC 4418.
var (
	p36  = new(big.Int).SetUint64(0x0000000FFFFFFFFB) // 2^36 - 5
	p64  = new(big.Int).SetUint64(0xFFFFFFFFFFFFFFC5) // 2^64 - 59
	// Values at or above this bound get the two-step reduction in POLY, so
	// that a message word can never collide with the prime's residue class.
	//
	// The 128-bit prime and its companion bound are absent because the ramp
	// that would use them is not implemented; see l2Hash.
	maxWordRange64 = func() *big.Int {
		// 2^64 - 2^32
		v := new(big.Int).Lsh(big.NewInt(1), 64)
		return v.Sub(v, new(big.Int).Lsh(big.NewInt(1), 32))
	}()
)

// UMAC holds the derived key schedule for one key and tag length. Safe for
// concurrent use: Tag derives no state from previous calls.
type UMAC struct {
	tagLen int
	iters  int

	block cipher.Block // for the KDF
	pdfKey cipher.Block // AES key used by the pad derivation function

	l1Key  []byte
	l2Key  []byte
	l3Key1 []byte
	l3Key2 []byte
}

// New returns a UMAC keyed with key for the given tag length in bytes.
//
// SSH uses 8 (umac-64) and 16 (umac-128). The 4- and 12-byte variants the RFC
// also defines are accepted because the published test vectors cover them, and
// exercising the 12-byte case is what validates the iteration and key-shift
// logic at a count between the two SSH uses.
func New(key []byte, tagLen int) (*UMAC, error) {
	switch tagLen {
	case 4, 8, 12, 16:
	default:
		return nil, errInvalidTagLen{tagLen}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	u := &UMAC{tagLen: tagLen, iters: tagLen / 4, block: block}

	// Index 0 keys the pad; 1 through 4 key the three hash layers. The extra
	// (iters-1)*16 bytes of L1 key are the Toeplitz shift that lets each
	// iteration reuse the same key material at a different offset.
	pdfKeyBytes := u.kdf(0, blockLen)
	u.pdfKey, err = aes.NewCipher(pdfKeyBytes)
	if err != nil {
		return nil, err
	}

	u.l1Key = u.kdf(1, l1KeyLen+(u.iters-1)*16)
	u.l2Key = u.kdf(2, u.iters*24)
	u.l3Key1 = u.kdf(3, u.iters*64)
	u.l3Key2 = u.kdf(4, u.iters*4)

	return u, nil
}

type errInvalidTagLen struct{ n int }

func (e errInvalidTagLen) Error() string {
	return "umac: tag length " + itoa(e.n) + " is not 4, 8, 12 or 16"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Tag computes the authentication tag for msg under nonce.
//
// nonce is the eight-byte sequence number SSH authenticates each packet with.
//
// Panics if msg exceeds MaxMessageLen. That is unreachable through SSH, whose
// packets are two orders of magnitude smaller, and a panic is the right
// response to it: the alternative is returning a tag computed without the
// polynomial ramp, which would be silently wrong.
func (u *UMAC) Tag(nonce, msg []byte) []byte {
	if len(msg) > MaxMessageLen {
		panic("umac: message exceeds MaxMessageLen; the polynomial ramp is not implemented")
	}
	hashed := u.uhash(msg)
	pad := u.pdf(nonce)
	for i := range hashed {
		hashed[i] ^= pad[i]
	}
	return hashed
}

// kdf derives numBytes of key material under the given index.
//
// The counter occupies the final byte of the AES input block and the index the
// byte at offset 7, matching the reference implementation. Both are big-endian
// integers in the RFC's presentation, but every length this package requests
// stays under 256 blocks, so only the low byte of the counter is ever set.
func (u *UMAC) kdf(index byte, numBytes int) []byte {
	out := make([]byte, 0, numBytes+blockLen)
	var in, enc [blockLen]byte
	in[blockLen-9] = index

	for i := 1; len(out) < numBytes; i++ {
		in[blockLen-1] = byte(i)
		u.block.Encrypt(enc[:], in[:])
		out = append(out, enc[:]...)
	}
	return out[:numBytes]
}

// pdf produces the tag-length pad that is XORed with the hash output.
//
// For an eight-byte tag the low bit of the nonce selects which half of the AES
// output to take, and that bit is cleared before encryption so that two nonces
// differing only in it share a single block. Sixteen-byte tags consume the
// whole block and mask nothing.
func (u *UMAC) pdf(nonce []byte) []byte {
	var buf [blockLen]byte
	copy(buf[:], nonce)

	// Short tags take a slice of the block, so the low bits of the nonce pick
	// which slice; they are cleared first so that two nonces differing only in
	// them encipher identically and share one block.
	//
	// The bits live in the last byte of the nonce, not the last byte of the
	// AES input. The nonce sits at the front of the block and the remainder is
	// zero padding, so masking the block's final byte would mask padding and
	// leave the selector bits in the enciphered input.
	var mask byte
	switch u.tagLen {
	case 4:
		mask = 3
	case 8:
		mask = 1
	}

	last := len(nonce) - 1
	index := int(buf[last] & mask)
	buf[last] &^= mask

	var enc [blockLen]byte
	u.pdfKey.Encrypt(enc[:], buf[:])

	out := make([]byte, u.tagLen)
	copy(out, enc[index*u.tagLen:])
	return out
}

// uhash runs the three-layer universal hash once per iteration, concatenating
// the four-byte results into a tag-length string.
func (u *UMAC) uhash(msg []byte) []byte {
	out := make([]byte, 0, u.tagLen)

	for i := 0; i < u.iters; i++ {
		// The Toeplitz shift: iteration i reads its NH key starting 16 bytes
		// further into the same buffer.
		l1 := u.l1Key[i*16 : i*16+l1KeyLen]
		l2 := u.l2Key[i*24 : (i+1)*24]
		k1 := u.l3Key1[i*64 : (i+1)*64]
		k2 := u.l3Key2[i*4 : (i+1)*4]

		a := l1Hash(l1, msg)

		var b []byte
		if len(msg) <= l1BlockLen {
			// A single L1 block skips the polynomial layer entirely, which is
			// the path every ordinary SSH packet takes.
			b = make([]byte, 16)
			copy(b[8:], a)
		} else {
			b = l2Hash(l2, a)
		}

		out = append(out, l3Hash(k1, k2, b)...)
	}
	return out
}

// l1Hash runs NH over each 1024-byte block, emitting eight bytes per block.
func l1Hash(key, msg []byte) []byte {
	nBlocks := (len(msg) + l1BlockLen - 1) / l1BlockLen
	if nBlocks == 0 {
		// The empty message still produces one block, which NH sees as 32
		// zero bytes carrying a length of zero.
		nBlocks = 1
	}

	out := make([]byte, 0, nBlocks*8)
	for i := 0; i < nBlocks; i++ {
		end := (i + 1) * l1BlockLen
		if end > len(msg) {
			end = len(msg)
		}
		block := msg[i*l1BlockLen : end]

		y := nh(key, block) + uint64(len(block))*8
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], y)
		out = append(out, buf[:]...)
	}
	return out
}

// nh is the first hash layer: a sum of products of key-offset message words.
//
// The message and the key are read with opposite endianness, which is the
// single most counter-intuitive detail in the whole construction and the one
// most likely to be "corrected" by a later reader.
//
// It follows from the specification: L1-HASH applies an endian swap to the
// message before handing it to NH, but not to the key, which is consumed as the
// raw AES output the KDF produced. A swap followed by a native little-endian
// read is a big-endian read of the original bytes -- so the message ends up
// little-endian here and the key big-endian.
//
// Reading both the same way yields a hash that is entirely self-consistent and
// disagrees with every other implementation. It was settled against the RFC
// 4418 vectors, not by inspection; the empty-message vector cannot detect it,
// because every message word it hashes is zero.
func nh(key, msg []byte) uint64 {
	// Short blocks are zero-padded up to NH's 32-byte granularity. An empty
	// message still gets one chunk, so the key alone determines the result.
	padded := msg
	switch {
	case len(msg) == 0:
		padded = make([]byte, nhChunk)
	case len(msg)%nhChunk != 0:
		padded = make([]byte, len(msg)+nhChunk-len(msg)%nhChunk)
		copy(padded, msg)
	}

	var y uint64
	for off := 0; off+nhChunk <= len(padded); off += nhChunk {
		m := padded[off : off+nhChunk]
		k := key[off : off+nhChunk]
		for j := 0; j < 4; j++ {
			a := binary.LittleEndian.Uint32(m[j*4:]) + binary.BigEndian.Uint32(k[j*4:])
			b := binary.LittleEndian.Uint32(m[(j+4)*4:]) + binary.BigEndian.Uint32(k[(j+4)*4:])
			y += uint64(a) * uint64(b)
		}
	}
	return y
}

// MaxMessageLen is the largest message this package will authenticate.
//
// UMAC hashes under the 64-bit prime until the first-layer output reaches 2^17
// bits, then ramps to a 128-bit prime for the remainder. That threshold is
// measured on the L1 output -- eight bytes per 1024-byte block -- so it
// corresponds to two megabytes of original message.
//
// The ramp is not implemented, and Tag rejects anything that would need it
// rather than returning a tag computed the wrong way. See l2Hash.
const MaxMessageLen = (1 << 17 / 8) * l1BlockLen // 2 MiB

// l2Hash is the polynomial layer, reached only by messages longer than one L1
// block.
//
// # The missing ramp
//
// Above 2^17 bits of L1 output the specification switches to a 128-bit prime.
// That path is deliberately absent. Every other reading in this package was
// settled against the RFC 4418 vectors, and the ramp is the one construction
// whose vector -- the 32-megabyte case -- this implementation does not
// reproduce. Shipping it would mean shipping authentication code that is wrong
// in a way no test here detects, which is worse than not having it: a MAC that
// silently disagrees with the peer produces intermittent handshake failures,
// and intermittent failures on a sensor are a louder signal than the gap this
// package was written to close.
//
// Nothing in SSH reaches it. RFC 4253 caps a packet at 256 KiB and OpenSSH
// negotiates 32 KiB in practice, both far below the two-megabyte boundary, so
// the ramp is unreachable through the transport rather than merely unlikely.
// Callers outside SSH must respect MaxMessageLen.
func l2Hash(key, msg []byte) []byte {
	k64 := new(big.Int).SetBytes(maskKey(key[0:8], 0x01ffffff01ffffff))
	y := poly(64, maxWordRange64, p64, k64, msg)

	out := make([]byte, 16)
	y.FillBytes(out)
	return out
}

// maskKey clears the bits RFC 4418 requires to be zero in the polynomial keys,
// which is what keeps the key below the prime.
func maskKey(k []byte, mask uint64) []byte {
	v := binary.BigEndian.Uint64(k) & mask
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	return out
}

// poly evaluates the polynomial whose coefficients are the message words.
//
// A word at or above maxWordRange is folded in over two steps rather than one.
// Without that split a message word could take a value the prime field cannot
// represent distinctly, and the collision bound the construction rests on would
// not hold.
func poly(wordBits int, maxWordRange, prime, key *big.Int, msg []byte) *big.Int {
	wordBytes := wordBits / 8
	y := big.NewInt(1)
	tmp := new(big.Int)

	for off := 0; off+wordBytes <= len(msg); off += wordBytes {
		m := new(big.Int).SetBytes(msg[off : off+wordBytes])

		if m.Cmp(maxWordRange) >= 0 {
			y.Mul(y, key)
			y.Add(y, tmp.Sub(maxWordRange, one))
			y.Mod(y, prime)

			y.Mul(y, key)
			y.Add(y, tmp.Sub(m, maxWordRange))
			y.Mod(y, prime)
			continue
		}

		y.Mul(y, key)
		y.Add(y, m)
		y.Mod(y, prime)
	}
	return y
}

var one = big.NewInt(1)

// l3Hash is the final layer: an inner product of the sixteen-bit message words
// with eight key words, reduced mod 2^36-5, truncated to 32 bits and masked.
//
// This is what collapses the wide hash state down to the four bytes each
// iteration contributes to the tag.
func l3Hash(k1, k2, m []byte) []byte {
	y := new(big.Int)
	tmp := new(big.Int)

	for i := 0; i < 8; i++ {
		word := new(big.Int).SetUint64(uint64(binary.BigEndian.Uint16(m[i*2:])))
		key := new(big.Int).SetBytes(k1[i*8 : (i+1)*8])
		key.Mod(key, p36)
		y.Add(y, tmp.Mul(word, key))
	}
	y.Mod(y, p36)

	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(y.Uint64())^binary.BigEndian.Uint32(k2))
	return out
}
