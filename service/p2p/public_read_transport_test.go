package p2p

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xssnick/gton/service/archive"
	tonnodeapi "github.com/xssnick/tonutils-go/adnl/node"
	"github.com/xssnick/tonutils-go/adnl/overlay"
	adnlquic "github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

func TestPublicReadTransportVersion(t *testing.T) {
	peer, _ := testArchiveDownloadPeerWithRLDP(t, "legacy", 1, nil, 0)
	quicPeer, _ := testArchiveDownloadPeerWithRLDP(t, "new", 1, nil, 0)
	quicTransport := &quicPeerQueryTransport{peer: quicPeer}
	peer.publicQUIC = quicTransport
	peer.applyCapabilities(Capabilities{VersionMajor: 3, VersionMinor: 2})
	if _, ok := peer.readTransport(t.Context()).(rldpPeerQueryTransport); !ok {
		t.Fatal("3.2 public peer did not keep RLDP")
	}
	for _, cap := range []Capabilities{
		{VersionMajor: 3, VersionMinor: 3}, {VersionMajor: 3, VersionMinor: 4}, {VersionMajor: 4},
	} {
		peer.applyCapabilities(cap)
		if peer.readTransport(t.Context()) != quicTransport {
			t.Fatalf("public peer %d.%d did not choose QUIC", cap.VersionMajor, cap.VersionMinor)
		}
	}
}

func TestPublicQUICReplayIncidentDownloads(t *testing.T) {
	dir := os.Getenv("GTON_INCIDENT_FIXTURES")
	if dir == "" {
		t.Skip("set GTON_INCIDENT_FIXTURES to the captured incident package, block and proof")
	}
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	pack, blockBOC, proofBOC := read("incident.pack"), read("incident.block.boc"), read("incident.proof.boc")
	root, err := cell.FromBOC(blockBOC)
	if err != nil {
		t.Fatal(err)
	}
	rootHash, fileHash := root.HashKey(), sha256.Sum256(blockBOC)
	block := ton.BlockIDExt{Workchain: 0, Shard: topShard, SeqNo: 111923229, RootHash: rootHash[:], FileHash: fileHash[:]}

	node := newTestNode(t)
	node.zeroStateFileHash = make([]byte, 32)
	t.Cleanup(func() { _ = node.quicGateway.Close() })
	shard := archive.ShardID{Workchain: 0, Shard: topShard}
	sub, err := node.querySubscriptionForArchive(shard)
	if err != nil {
		t.Fatal(err)
	}
	const archiveID = 1507640540896
	peer, rldp := testArchiveDownloadPeerWithRLDP(t, "incident-quic", 123, testArchivePackBytes("wrong pack"), 0)
	var capabilityProbes atomic.Int32
	server, err := adnlquic.NewGateway(quicOutboundTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	server.SetConnectionHandler(func(remote *adnlquic.Peer) error {
		remote.SetQueryHandler(func(_ context.Context, payload []byte) ([]byte, error) {
			var envelope overlay.Query
			req, err := parseQUICOverlayObject(payload, &envelope)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(envelope.Overlay, sub.spec.ShortID) {
				return nil, errors.New("unexpected public overlay")
			}
			switch req := req.(type) {
			case GetCapabilities:
				capabilityProbes.Add(1)
				return tl.Serialize(Capabilities{VersionMajor: 3, VersionMinor: 3}, true)
			case GetShardArchiveInfo:
				if req.MasterchainSeqno != 107037535 || req.ShardPrefix.Workchain != shard.Workchain || req.ShardPrefix.Shard != shard.Shard {
					return nil, fmt.Errorf("unexpected archive request: %+v", req)
				}
				peer.applyCapabilities(Capabilities{VersionMajor: 3, VersionMinor: 2})
				return tl.Serialize(ArchiveInfo{ID: archiveID}, true)
			case GetArchiveSlice:
				if req.ArchiveID != archiveID || req.Offset < 0 || req.MaxSize <= 0 {
					return nil, fmt.Errorf("unexpected archive slice: %+v", req)
				}
				if req.Offset >= int64(len(pack)) {
					return nil, nil
				}
				return pack[req.Offset:min(req.Offset+int64(req.MaxSize), int64(len(pack)))], nil
			case tonnodeapi.DownloadBlockFull:
				if !req.Block.Equals(&block) {
					return nil, errors.New("unexpected block identity")
				}
				return tl.Serialize(tonnodeapi.DataFull{ID: block, Block: blockBOC, Proof: proofBOC, IsLink: true}, true)
			default:
				return nil, fmt.Errorf("unexpected QUIC query %T", req)
			}
		})
		return nil
	})
	endpoint := startQUICOutboundTestGateway(t, server)
	peer.node = node
	peer.id, err = NewPeerID(server.ID())
	if err != nil {
		t.Fatal(err)
	}
	peer.pub = server.PublicKey()
	peer.route = newTestPeerRoute(endpoint)
	peer.publicQUIC = &quicPeerQueryTransport{peer: peer, envelope: sub.quicEnvelope}
	var adnl *testOverlayADNL
	peer.overlay, adnl = newTestOverlayWrapper()
	adnl.queryResponder = func(req tl.Serializable, result tl.Serializable) error {
		if _, ok := testOverlayQueryPayload(req).(overlay.GetRandomPeers); ok {
			*result.(*overlay.NodesList) = overlay.NodesList{}
			return nil
		}
		return context.DeadlineExceeded
	}

	session := node.BeginArchiveSession()
	defer session.Close()
	pool, err := session.archivePeerPool(sub)
	if err != nil {
		t.Fatal(err)
	}
	if !addTestArchiveOnlyPeer(pool, peer) {
		t.Fatal("could not seed the incident archive peer")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	got, err := session.DownloadArchive(ctx, 107037535, shard, ArchiveDownloadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.ArchiveID != archiveID || !bytes.Equal(got.Data, pack) {
		t.Fatalf("unexpected package: archive=%d bytes=%d", got.ArchiveID, len(got.Data))
	}

	peer.applyCapabilities(Capabilities{VersionMajor: 3, VersionMinor: 3})
	decoded, err := sub.queryFromPeer(ctx, peer, tonnodeapi.DownloadBlockFull{Block: block})
	if err != nil {
		t.Fatal(err)
	}
	full, ok := decoded.(tonnodeapi.DataFull)
	if !ok || !full.ID.Equals(&block) || sha256.Sum256(full.Block) != fileHash {
		t.Fatalf("incident block did not pass the file hash check: %T", decoded)
	}
	if got := capabilityProbes.Load(); got != 1 {
		t.Fatalf("cold peer capability probes = %d, want 1", got)
	}
	if queries := len(rldp.snapshot().asyncQueries); queries != 0 {
		t.Fatalf("modern peer used RLDP %d times", queries)
	}
	t.Logf("public QUIC read returned exact shard %d and full archive %d (%d bytes)", block.SeqNo, archiveID, len(got.Data))
}
