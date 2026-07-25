// Package spool is the node's write-ahead log.
//
// Events are durably appended here before any attempt to publish them. A node
// on a flaky VPS link, or one whose collector is being restarted, must not lose
// the sessions it observed in the meantime -- those are frequently the
// interesting ones, since an attacker knocking the collector over is itself the
// event you want recorded.
//
// The log is bounded. When it fills, the oldest entries are dropped and a
// counter increments, which is surfaced in NodeHeartbeat. Silent data loss is
// worse than known data loss: an analyst who does not know the corpus has holes
// will read the gaps as attacker behaviour.
package spool

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	pb "github.com/honeynet/node/gen/honeynet/v1"
)

var (
	bucketEvents = []byte("events")
	bucketMeta   = []byte("meta")
	keySeq       = []byte("seq")
)

// Spool is a durable FIFO of pending envelopes.
type Spool struct {
	db       *bbolt.DB
	maxBytes int64
	dropped  atomic.Uint64
}

// Options configure a Spool.
type Options struct {
	Path     string
	MaxBytes int64
}

// DefaultOptions bounds the spool at 256 MiB, which holds on the order of a
// million events -- days of traffic for a single sensor.
func DefaultOptions(path string) Options {
	return Options{Path: path, MaxBytes: 256 << 20}
}

// Open creates or reopens the spool at the given path.
func Open(opt Options) (*Spool, error) {
	db, err := bbolt.Open(opt.Path, 0o600, &bbolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open spool: %w", err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{bucketEvents, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init spool buckets: %w", err)
	}
	return &Spool{db: db, maxBytes: opt.MaxBytes}, nil
}

// Close flushes and releases the spool.
func (s *Spool) Close() error { return s.db.Close() }

// NextSeq reserves and persists the next per-node sequence number.
//
// The counter survives restart, which is what makes collector-side gap
// detection meaningful: a node that restarts and resets to 1 would look
// identical to a node replaying events.
func (s *Spool) NextSeq() (uint64, error) {
	var seq uint64
	err := s.db.Update(func(tx *bbolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		cur := uint64(0)
		if v := meta.Get(keySeq); len(v) == 8 {
			cur = binary.BigEndian.Uint64(v)
		}
		cur++
		seq = cur
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], cur)
		return meta.Put(keySeq, buf[:])
	})
	return seq, err
}

// Append assigns a sequence number, stamps it into the envelope, and durably
// stores the result.
func (s *Spool) Append(env *pb.Envelope) error {
	seq, err := s.NextSeq()
	if err != nil {
		return fmt.Errorf("reserve seq: %w", err)
	}
	env.Seq = seq

	blob, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketEvents)

		// Evict from the head until the new record fits. Dropping the oldest
		// keeps the most recent -- and most actionable -- observations.
		for int64(tx.Size())+int64(len(blob)) > s.maxBytes {
			c := b.Cursor()
			k, _ := c.First()
			if k == nil {
				break
			}
			if err := b.Delete(k); err != nil {
				return err
			}
			s.dropped.Add(1)
		}

		var key [8]byte
		binary.BigEndian.PutUint64(key[:], seq)
		return b.Put(key[:], blob)
	})
}

// Batch is a set of pending records handed to a publisher.
type Batch struct {
	Keys  [][]byte
	Blobs [][]byte
}

// Peek returns up to n pending records without removing them. Records are only
// deleted once Ack confirms the publisher accepted them, so a crash mid-publish
// re-delivers rather than loses.
func (s *Spool) Peek(n int) (Batch, error) {
	var batch Batch
	err := s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketEvents).Cursor()
		for k, v := c.First(); k != nil && len(batch.Keys) < n; k, v = c.Next() {
			key := append([]byte(nil), k...)
			blob := append([]byte(nil), v...)
			batch.Keys = append(batch.Keys, key)
			batch.Blobs = append(batch.Blobs, blob)
		}
		return nil
	})
	return batch, err
}

// Ack removes records the publisher confirmed.
func (s *Spool) Ack(keys [][]byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketEvents)
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// Depth reports how many records are pending publication.
func (s *Spool) Depth() (uint64, error) {
	var n uint64
	err := s.db.View(func(tx *bbolt.Tx) error {
		n = uint64(tx.Bucket(bucketEvents).Stats().KeyN)
		return nil
	})
	return n, err
}

// Dropped reports how many records were evicted because the bound was reached.
// Reported in NodeHeartbeat so the operator learns the corpus has holes.
func (s *Spool) Dropped() uint64 { return s.dropped.Load() }
