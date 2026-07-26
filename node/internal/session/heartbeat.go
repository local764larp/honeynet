package session

import (
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/honeynet/node/gen/honeynet/v1"
)

// EmitHeartbeat records node liveness and spool health.
//
// The dropped counter is the reason this exists. A sensor whose spool
// overflowed has holes in its corpus, and an analyst who reads those holes as
// quiet periods will draw wrong conclusions about campaign timing. Liveness is
// the lesser half of the message.
func EmitHeartbeat(nodeID string, sink Sink, uptime time.Duration, spoolDepth, spoolDropped uint64, activeSessions uint32, buildVersion string) error {
	return sink.Append(&pb.Envelope{
		NodeId:        nodeID,
		SessionId:     "",
		TsNode:        timestamppb.Now(),
		SchemaVersion: SchemaVersion,
		Event: &pb.Envelope_NodeHeartbeat{
			NodeHeartbeat: &pb.NodeHeartbeat{
				Uptime:         durationpb.New(uptime),
				SpoolDepth:     spoolDepth,
				SpoolDropped:   spoolDropped,
				ActiveSessions: activeSessions,
				BuildVersion:   buildVersion,
			},
		},
	})
}
