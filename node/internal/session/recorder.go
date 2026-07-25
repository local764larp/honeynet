// Package session turns protocol-handler observations into wire envelopes.
//
// It is the only place in the node that constructs protobuf messages, so every
// protocol handler stays free of schema details and the schema stays free of
// protocol details.
package session

import (
	"crypto/md5" //nolint:gosec // HASSH is defined as MD5; interoperability requires it
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"math/rand"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/honeynet/node/gen/honeynet/v1"
	"github.com/honeynet/node/internal/shell"
)

// SchemaVersion is stamped into every envelope. Bumped only for changes that
// protobuf's own compatibility rules cannot express.
const SchemaVersion = 1

// Sink accepts completed envelopes. The spool implements it.
type Sink interface {
	Append(*pb.Envelope) error
}

// Recorder builds and emits the events for one attacker session.
type Recorder struct {
	nodeID    string
	sessionID string
	sink      Sink
	log       *slog.Logger

	protocol pb.Protocol
	peer     *pb.Peer
	start    time.Time

	authIndex uint32
	lastAuth  time.Time

	commandCount uint32
	authCount    uint32
	bytesIn      uint64
	bytesOut     uint64
}

// NewID mints a ULID for a session. Lexicographic ordering matches creation
// order, which makes the identifier useful as a sort key downstream.
func NewID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), ulid.DefaultEntropy()).String()
}

// New creates a Recorder for one connection.
func New(nodeID string, sink Sink, log *slog.Logger, protocol pb.Protocol, peer *pb.Peer) *Recorder {
	now := time.Now()
	return &Recorder{
		nodeID:    nodeID,
		sessionID: NewID(),
		sink:      sink,
		log:       log,
		protocol:  protocol,
		peer:      peer,
		start:     now,
		lastAuth:  now,
	}
}

// ID returns the session's ULID.
func (r *Recorder) ID() string { return r.sessionID }

// Peer returns the remote endpoint.
func (r *Recorder) Peer() *pb.Peer { return r.peer }

// Elapsed returns how long the session has been open.
func (r *Recorder) Elapsed() time.Duration { return time.Since(r.start) }

func (r *Recorder) emit(env *pb.Envelope) {
	env.NodeId = r.nodeID
	env.SessionId = r.sessionID
	env.TsNode = timestamppb.Now()
	env.SchemaVersion = SchemaVersion

	if err := r.sink.Append(env); err != nil {
		// A spool write failure is serious but must never kill the session --
		// dropping the connection mid-transcript teaches the attacker that
		// something is watching.
		r.log.Error("spool append failed", "err", err, "session", r.sessionID)
	}
}

// SessionStart records the opening of a connection, including the client
// fingerprint material.
func (r *Recorder) SessionStart(banner string, kex, ciphers, macs, compression []string) {
	r.emit(&pb.Envelope{
		Event: &pb.Envelope_SessionStart{
			SessionStart: &pb.SessionStart{
				Protocol:               r.protocol,
				Peer:                   r.peer,
				ClientBanner:           banner,
				KexAlgorithms:          kex,
				Ciphers:                ciphers,
				Macs:                   macs,
				CompressionAlgorithms:  compression,
				Hassh:                  HASSH(kex, ciphers, macs, compression),
			},
		},
	})
}

// HASSH computes the client SSH fingerprint: MD5 over the semicolon-joined
// algorithm lists, comma-separated within each list.
//
// The value survives banner spoofing, because it derives from the client
// library's actual algorithm ordering rather than from a string the client
// chooses. That makes it the most reliable link between sessions from the same
// tool, and a strong clustering feature downstream.
func HASSH(kex, ciphers, macs, compression []string) string {
	joined := strings.Join([]string{
		strings.Join(kex, ","),
		strings.Join(ciphers, ","),
		strings.Join(macs, ","),
		strings.Join(compression, ","),
	}, ";")
	sum := md5.Sum([]byte(joined)) //nolint:gosec // HASSH is specified as MD5
	return hex.EncodeToString(sum[:])
}

// AuthAttempt records one credential offer.
func (r *Recorder) AuthAttempt(method pb.AuthMethod, username, password string, success bool) {
	now := time.Now()
	r.emit(&pb.Envelope{
		Event: &pb.Envelope_AuthAttempt{
			AuthAttempt: &pb.AuthAttempt{
				Method:        method,
				Username:      username,
				Password:      password,
				Success:       success,
				AttemptIndex:  r.authIndex,
				SincePrevious: durationpb.New(now.Sub(r.lastAuth)),
			},
		},
	})
	r.authIndex++
	r.authCount++
	r.lastAuth = now
}

// PublicKeyAttempt records a public-key offer. Repeated keys across sessions
// are among the strongest links between otherwise unrelated source addresses.
func (r *Recorder) PublicKeyAttempt(username, keyType string, keyBlob []byte, success bool) {
	now := time.Now()
	sum := sha256.Sum256(keyBlob)
	r.emit(&pb.Envelope{
		Event: &pb.Envelope_AuthAttempt{
			AuthAttempt: &pb.AuthAttempt{
				Method:          pb.AuthMethod_AUTH_METHOD_PUBLICKEY,
				Username:        username,
				PublicKeySha256: hex.EncodeToString(sum[:]),
				PublicKeyType:   keyType,
				Success:         success,
				AttemptIndex:    r.authIndex,
				SincePrevious:   durationpb.New(now.Sub(r.lastAuth)),
			},
		},
	})
	r.authIndex++
	r.authCount++
	r.lastAuth = now
}

// Command records a line of attacker input with its timing metadata.
func (r *Recorder) Command(ev shell.CommandEvent) {
	r.commandCount++
	r.emit(&pb.Envelope{
		Event: &pb.Envelope_CommandInput{
			CommandInput: &pb.CommandInput{
				Raw:                ev.Raw,
				Argv:               ev.Argv,
				ParseFailed:        ev.ParseFailed,
				Cwd:                ev.Cwd,
				SinceSessionStart:  durationpb.New(ev.SinceStart),
				SincePrevious:      durationpb.New(ev.SincePrev),
				KeystrokeDeltasMs:  ev.KeystrokeDeltasMS,
				BulkInput:          ev.BulkInput,
				CommandIndex:       ev.Index,
			},
		},
	})
}

// Artifact records a URL the attacker asked the node to fetch. The node does
// not fetch it -- see design doc section 4.2.
func (r *Recorder) Artifact(ev shell.ArtifactEvent) {
	scheme, host, port, urlPath := splitURL(ev.URL)
	r.emit(&pb.Envelope{
		Event: &pb.Envelope_ArtifactReference{
			ArtifactReference: &pb.ArtifactReference{
				Url:           ev.URL,
				Scheme:        scheme,
				Host:          host,
				Port:          port,
				Path:          urlPath,
				ViaTool:       ev.ViaTool,
				SourceCommand: ev.SourceCommand,
			},
		},
	})
}

// Upload records bytes the attacker actually pushed to the node.
func (r *Recorder) Upload(ev shell.UploadEvent) {
	sum := sha256.Sum256(ev.Content)
	prefix := ev.Content
	if len(prefix) > 64 {
		prefix = prefix[:64]
	}
	r.emit(&pb.Envelope{
		Event: &pb.Envelope_FileUpload{
			FileUpload: &pb.FileUpload{
				Sha256:       hex.EncodeToString(sum[:]),
				SizeBytes:    uint64(len(ev.Content)),
				ClaimedName:  ev.ClaimedName,
				Transport:    ev.Transport,
				MagicPrefix:  prefix,
				DetectedType: detectType(ev.Content),
			},
		},
	})
}

// HTTPRequestEvent is one request against a web decoy.
type HTTPRequestEvent struct {
	Method          string
	Path            string
	Query           string
	Version         string
	Headers         map[string]string
	BodySHA256      string
	BodySize        uint64
	DecoyProfile    string
	ResponseStatus  uint32
	DetectedAttacks []string
	FormUsername    string
	FormPassword    string
}

// HTTPRequest records a request against a web decoy.
func (r *Recorder) HTTPRequest(ev HTTPRequestEvent) {
	r.commandCount++
	r.emit(&pb.Envelope{
		Event: &pb.Envelope_HttpRequest{
			HttpRequest: &pb.HttpRequest{
				Method:          ev.Method,
				Path:            ev.Path,
				Query:           ev.Query,
				Version:         ev.Version,
				Headers:         ev.Headers,
				BodySha256:      ev.BodySHA256,
				BodySize:        ev.BodySize,
				DecoyProfile:    ev.DecoyProfile,
				ResponseStatus:  ev.ResponseStatus,
				DetectedAttacks: ev.DetectedAttacks,
				FormUsername:    ev.FormUsername,
				FormPassword:    ev.FormPassword,
			},
		},
	})
}

// CanaryEvent is a planted token being touched.
type CanaryEvent struct {
	TokenID      string
	TokenType    string
	PlantedPath  string
	CallbackPeer *pb.Peer
	UserAgent    string
}

// Canary records a canary token callback.
//
// The callback source frequently differs from any session peer, and that
// difference is the interesting part: it shows the planted file left the
// network it was planted on.
func (r *Recorder) Canary(ev CanaryEvent) {
	r.emit(&pb.Envelope{
		Event: &pb.Envelope_CanaryTrigger{
			CanaryTrigger: &pb.CanaryTrigger{
				TokenId:      ev.TokenID,
				TokenType:    ev.TokenType,
				PlantedPath:  ev.PlantedPath,
				CallbackPeer: ev.CallbackPeer,
				UserAgent:    ev.UserAgent,
			},
		},
	})
}

// RDPConnectEvent is an RDP handshake, with whatever the client disclosed
// before the negotiation was abandoned.
type RDPConnectEvent struct {
	Cookie             string
	Domain             string
	Username           string
	Password           string
	ClientBuild        string
	ClientName         string
	RequestedProtocols []string
}

// RDPConnect records an RDP connection attempt.
func (r *Recorder) RDPConnect(ev RDPConnectEvent) {
	r.emit(&pb.Envelope{
		Event: &pb.Envelope_RdpConnect{
			RdpConnect: &pb.RdpConnect{
				Cookie:             ev.Cookie,
				Domain:             ev.Domain,
				Username:           ev.Username,
				Password:           ev.Password,
				ClientBuild:        ev.ClientBuild,
				ClientName:         ev.ClientName,
				RequestedProtocols: ev.RequestedProtocols,
			},
		},
	})
}

// SessionEnd closes the session record.
func (r *Recorder) SessionEnd(reason pb.SessionEndReason, pcapSHA string) {
	r.emit(&pb.Envelope{
		Event: &pb.Envelope_SessionEnd{
			SessionEnd: &pb.SessionEnd{
				Reason:       reason,
				Duration:     durationpb.New(time.Since(r.start)),
				CommandCount: r.commandCount,
				AuthAttempts: r.authCount,
				BytesIn:      r.bytesIn,
				BytesOut:     r.bytesOut,
				PcapSha256:   pcapSHA,
			},
		},
	})
}

// Anomaly records the node misbehaving or defending itself.
func (r *Recorder) Anomaly(kind, detail string) {
	r.emit(&pb.Envelope{
		Event: &pb.Envelope_NodeAnomaly{
			NodeAnomaly: &pb.NodeAnomaly{Kind: kind, Detail: detail, Peer: r.peer},
		},
	})
}

// CountBytes accumulates transfer volume for the SessionEnd summary.
func (r *Recorder) CountBytes(in, out uint64) {
	r.bytesIn += in
	r.bytesOut += out
}

func splitURL(u string) (scheme, host string, port uint32, urlPath string) {
	rest := u
	for _, s := range []string{"http://", "https://", "ftp://", "tftp://"} {
		if strings.HasPrefix(strings.ToLower(rest), s) {
			scheme = strings.TrimSuffix(s, "://")
			rest = rest[len(s):]
			break
		}
	}
	switch scheme {
	case "https":
		port = 443
	case "ftp":
		port = 21
	case "tftp":
		port = 69
	default:
		port = 80
	}

	if i := strings.IndexByte(rest, '/'); i >= 0 {
		host, urlPath = rest[:i], rest[i:]
	} else {
		host, urlPath = rest, "/"
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		if v := host[i+1:]; v != "" {
			var n uint32
			for _, c := range v {
				if c < '0' || c > '9' {
					n = 0
					break
				}
				n = n*10 + uint32(c-'0')
			}
			if n > 0 {
				port = n
				host = host[:i]
			}
		}
	}
	return scheme, host, port, urlPath
}

// detectType classifies uploaded bytes by magic number. Deliberately shallow:
// precise identification is the collector's job, where a full signature
// database can live without bloating the sensor.
func detectType(b []byte) string {
	switch {
	case len(b) >= 4 && string(b[:4]) == "\x7fELF":
		return "application/x-elf"
	case len(b) >= 2 && string(b[:2]) == "MZ":
		return "application/x-dosexec"
	case len(b) >= 2 && string(b[:2]) == "#!":
		return "text/x-script"
	case len(b) >= 4 && string(b[:4]) == "PK\x03\x04":
		return "application/zip"
	case len(b) >= 3 && string(b[:3]) == "\x1f\x8b\x08":
		return "application/gzip"
	case len(b) == 0:
		return "application/x-empty"
	}
	if isMostlyText(b) {
		return "text/plain"
	}
	return "application/octet-stream"
}

func isMostlyText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return printable*10 >= len(b)*9
}

// Jitter returns a duration drawn around base with +/- spread, used to make
// emulated response latency non-uniform.
func Jitter(baseMS, spreadMS int) time.Duration {
	if spreadMS <= 0 {
		return time.Duration(baseMS) * time.Millisecond
	}
	delta := rand.Intn(spreadMS*2) - spreadMS //nolint:gosec // timing realism, not security
	ms := baseMS + delta
	if ms < 0 {
		ms = 0
	}
	return time.Duration(ms) * time.Millisecond
}
