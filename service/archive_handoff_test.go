package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xssnick/gton/service/archive"
	"github.com/xssnick/gton/service/storage"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type handoffStore struct{ ArchiveStore }

func (handoffStore) BlockState(context.Context, ton.BlockIDExt) (*storage.BlockState, error) {
	return nil, storage.ErrNotFound
}

type handoffPeers struct {
	archiveRunnerTransitionsStub
	masters        map[uint32]*storage.BlockState
	targets        map[uint32]ton.BlockIDExt
	available      map[uint32]PreparedBlock
	masterReads    int
	shardReads     int
	masterApplies  int
	shardApplies   int
	silentOnMiss   bool
	checkOnMiss    func()
	advanced       []uint32
	slowApplySeqno uint32
}

func (p *handoffPeers) probeArchiveSuccessor(ctx context.Context, prev *storage.BlockState) (PreparedBlock, []ton.BlockIDExt, error) {
	p.masterReads++
	if _, ok := ctx.Deadline(); !ok {
		return PreparedBlock{}, nil, errors.New("unbounded live master probe")
	}
	next := p.masters[prev.Block.SeqNo+1].Block
	block := PreparedBlock{
		ID:        next,
		Meta:      &storage.BlockMeta{ID: next, PrevRefs: []ton.BlockIDExt{prev.Block}},
		consensus: &masterchainConsensusProof{block: next, prevRef: prev.Block},
	}
	return block, []ton.BlockIDExt{p.targets[next.SeqNo]}, nil
}

func (p *handoffPeers) probeArchiveShard(ctx context.Context, id ton.BlockIDExt) (PreparedBlock, error) {
	p.shardReads++
	if _, ok := ctx.Deadline(); !ok {
		return PreparedBlock{}, errors.New("unbounded live shard probe")
	}
	if b, ok := p.available[id.SeqNo]; ok {
		return b, nil
	}
	if p.checkOnMiss != nil {
		p.checkOnMiss()
	}
	if p.silentOnMiss {
		<-ctx.Done()
		return PreparedBlock{}, ctx.Err()
	}
	return PreparedBlock{}, storage.ErrNotFound
}

func (p *handoffPeers) applyArchiveMasterBlock(ctx context.Context, _ *storage.BlockState, b *PreparedBlock, _ *masterchainConsensusProof, _ stateUpdateApplier, _ *blockAppliedObserverMeta) (*storage.BlockState, masterchainApplyTiming, time.Duration, error) {
	if b.ID.SeqNo == p.slowApplySeqno {
		timer := time.NewTimer(nextBlockBootstrapProbeTimeout + 100*time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, masterchainApplyTiming{}, 0, ctx.Err()
		case <-timer.C:
		}
	}
	p.masterApplies++
	return p.masters[b.ID.SeqNo], masterchainApplyTiming{}, 0, nil
}

func (p *handoffPeers) applyArchiveShardBlock(_ context.Context, id ton.BlockIDExt, previous []*storage.BlockState, b PreparedBlock, _ stateUpdateApplier, _ *blockAppliedObserverMeta) (*storage.BlockState, error) {
	p.shardApplies++
	if len(previous) != 1 || !previous[0].Block.Equals(&b.Meta.PrevRefs[0]) {
		return nil, errors.New("shard predecessor mismatch")
	}
	return &storage.BlockState{Block: id, Cell: cell.BeginCell().EndCell(), Parsed: &tlb.ShardStateUnsplit{}}, nil
}

func (p *handoffPeers) archiveCurrentAdvanced(current *storage.CurrentState) {
	p.advanced = append(p.advanced, current.ShardClientSeqno)
}

func TestArchiveHandoffMissingShard(t *testing.T) {
	for _, tc := range []struct {
		name      string
		silent    bool
		slowApply bool
	}{{name: "refused"}, {name: "silent", silent: true}, {name: "slow_apply", slowApply: true}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testArchiveHandoffMissingShard(t, tc.silent, tc.slowApply)
		})
	}
}

func testArchiveHandoffMissingShard(t *testing.T, silent, slowApply bool) {
	t.Helper()
	const (
		first          = uint32(150)
		missing        = uint32(211)
		archiveWindows = 2
		liveSeqno      = first + archiveWindows + 1
		liveShardSeqno = missing + archiveWindows
	)
	shard := func(n uint32) ton.BlockIDExt { return testBlockID(0, topShard, n) }
	prepared := func(n uint32) PreparedBlock {
		id := shard(n)
		return PreparedBlock{ID: id, Meta: &storage.BlockMeta{ID: id, PrevRefs: []ton.BlockIDExt{shard(n - 1)}}}
	}
	previous := shard(missing - 1)
	shardKey := storage.ShardKeyFromBlock(previous)
	currentMaster := testShardTargetsMasterState(t, testMasterBlockID(first), previous)
	currentMaster.Parsed.GenUTime = uint32(time.Now().Add(-164 * time.Second).Unix())
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	p := &handoffPeers{
		silentOnMiss: silent,
		masters:      make(map[uint32]*storage.BlockState),
		targets:      make(map[uint32]ton.BlockIDExt),
		available:    make(map[uint32]PreparedBlock),
	}
	importCache := newArchiveImportCache()
	previousMaster := currentMaster.Block
	for seqno := first + 1; seqno <= liveSeqno; seqno++ {
		genUTime := currentMaster.Parsed.GenUTime + 6*(seqno-first)
		shardSeqno := missing + seqno - first - 1
		master := testMasterBlockID(seqno)
		if seqno < liveSeqno {
			archivedMaster := testHandoffArchiveMaster(t, previousMaster, genUTime)
			master = archivedMaster.ID
			for _, block := range []PreparedBlock{archivedMaster, prepared(shardSeqno)} {
				key := archiveImportCacheKey{
					masterchainSeqno: seqno,
					shard:            archive.ShardID{Workchain: block.ID.Workchain, Shard: topShard},
				}
				_, err := importCache.load(ctx, key, func(context.Context) (*archiveImportResult, error) {
					return &archiveImportResult{
						stats:  &archive.ImportStats{Blocks: 1},
						blocks: map[storage.BlockRootHash]PreparedBlock{storage.BlockKey(block.ID): block},
					}, nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		p.targets[seqno] = shard(shardSeqno)
		state := testShardTargetsMasterState(t, master, p.targets[seqno])
		state.Parsed.GenUTime = genUTime
		p.masters[seqno] = state
		previousMaster = master
	}
	run := &archiveCatchUpRun{
		ctx:    ctx,
		target: p.masters[liveSeqno].Block,
		current: &storage.CurrentState{
			Masterchain:      *currentMaster,
			ShardClientSeqno: first,
			Shards: map[storage.ShardKey]storage.BlockState{
				shardKey: {Block: previous, Cell: cell.BeginCell().EndCell(), Parsed: &tlb.ShardStateUnsplit{}},
			},
		},
		archive: &ArchiveRunner{
			network:            archiveRunnerNetworkStub{observed: p.masters[liveSeqno].Block},
			prefetchWindows:    2,
			storage:            handoffStore{},
			masterTransitions:  p,
			shardTransitions:   p,
			currentTransitions: p,
			state:              &StateLifecycle{status: &StatusTracker{}},
		},
		importCache: importCache,
		stateCells:  newTestStateCellWindowCache(nil),
	}
	run.pipeline = run.startShardClientArchiveWindowPipeline()
	defer run.pipeline.stop()

	p.checkOnMiss = func() {
		_, hits := importCache.stats()
		if hits != 2*uint64(p.shardReads-1) || len(run.pipeline.done) != 0 {
			t.Error("another archive window was prepared before the missing live shard was tried")
		}
	}
	apply := func(window *shardClientArchiveWindow) {
		t.Helper()
		defer window.releaseImportedData()
		next, err := run.applyShardClientArchiveWindow(ctx, run.current, window)
		if err != nil {
			t.Fatal(err)
		}
		if err := run.commitAcceptedArchiveWindow(window, next); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= archiveWindows; i++ {
		start := time.Now()
		window, err := run.nextArchiveWindowWithProgress()
		fallbackTime := time.Since(start)
		if err != nil {
			t.Fatalf("live shard was missing and the planner produced no archive fallback: %v", err)
		}
		if silent && (fallbackTime < nextBlockBootstrapProbeTimeout || fallbackTime >= archiveCatchUpProgressInterval) {
			t.Fatalf("silent peer held archive for %v", fallbackTime)
		}
		seqno := first + uint32(i)
		if window.handoff != nil || window.startSeqno != seqno || window.shardArchives != 1 {
			t.Fatalf("unexpected fallback window: start=%d shard archives=%d", window.startSeqno, window.shardArchives)
		}
		_, hits := importCache.stats()
		if hits != 2*uint64(i) || p.masterReads != i || p.shardReads != i || p.masterApplies != i || len(p.advanced) != i-1 {
			t.Fatalf("fallback did not use the master and shard packs: cache hits=%d live reads=%d/%d master applies=%d advanced=%v", hits, p.masterReads, p.shardReads, p.masterApplies, p.advanced)
		}
		if w, err := run.liveHandoffWindow(); w != nil || err != nil || p.masterReads != i {
			t.Fatalf("repeated immediate probe: %v", err)
		}
		apply(window)
		last := run.current.Shards[shardKey].Block
		want := p.targets[seqno]
		if run.current.ShardClientSeqno != seqno || !last.Equals(&want) {
			t.Fatalf("archive fallback did not commit master %d and shard %d", seqno, want.SeqNo)
		}
		t.Logf("missing live shard: planned and selected archive in %v, committed master %d and shard %d", fallbackTime.Round(time.Millisecond), seqno, last.SeqNo)
		run.nextHandoffProbe = time.Time{} // the next live trial is due
	}

	p.available[liveShardSeqno] = prepared(liveShardSeqno)
	if slowApply {
		p.slowApplySeqno = liveSeqno
	}
	window, err := run.nextArchiveWindowWithProgress()
	if err != nil || window == nil || window.handoff == nil || run.current.ShardClientSeqno != liveSeqno-1 {
		t.Fatalf("available successor: handoff=%v err=%v", window != nil, err)
	}
	apply(window)
	last := run.current.Shards[shardKey].Block
	want := shard(liveShardSeqno)
	_, hits := importCache.stats()
	if !last.Equals(&want) || hits != 2*archiveWindows || len(p.advanced) != archiveWindows+1 ||
		p.masterReads != archiveWindows+1 || p.shardReads != archiveWindows+1 ||
		p.masterApplies != archiveWindows+1 || p.shardApplies != archiveWindows+1 {
		t.Fatalf("successor was skipped or repeated: advanced=%v cache hits=%d reads=%d/%d applies=%d/%d shard=%s", p.advanced, hits, p.masterReads, p.shardReads, p.masterApplies, p.shardApplies, storage.FormatBlockRef(last))
	}
	t.Logf("live restored: 1 additional master read and 1 shard read; committed %d with shard %d", run.current.ShardClientSeqno, last.SeqNo)
}

func testHandoffArchiveMaster(t *testing.T, previous ton.BlockIDExt, genUTime uint32) PreparedBlock {
	t.Helper()

	original := mustLoadFixtureDownloadedBlock(t)
	header := hardforkProofHeader(t, original.Block)
	header.SeqNo = previous.SeqNo + 1
	header.GenUtime = genUTime
	header.KeyBlock = true
	header.PrevRef = tlb.BlkPrevInfo{Prev1: tlb.ExtBlkRef{
		SeqNo:    previous.SeqNo,
		RootHash: previous.RootHash,
		FileHash: previous.FileHash,
	}}
	block := synthesizeHardforkProofBlock(t, original.Block, header, original.StateUpdate)
	return PreparedBlock{
		ID:        block.ID,
		Meta:      block.Meta,
		BlockRoot: block.Block,
		BlockBOC:  block.BlockBOC,
		ProofBOC:  block.ProofBOC,
	}
}
