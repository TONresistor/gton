package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/xssnick/gton/service/archive"
	"github.com/xssnick/gton/service/storage"
	"github.com/xssnick/tonutils-go/ton"
)

func (r *archiveCatchUpRun) liveHandoffWindow() (*shardClientArchiveWindow, error) {
	latest, err := r.archive.network.ObservedMasterchainBlock()
	if err == nil && shouldPreferNextBlockTarget(r.current.ShardClientSeqno, latest.SeqNo) && r.archive.network.IsHardfork(latest) {
		return nil, errArchiveNextBlockReady
	}
	now := time.Now()
	if now.Before(r.nextHandoffProbe) {
		return nil, nil
	}
	master := &r.current.Masterchain
	stamp := blockStateUtime(r.ctx, r.archive.storage, master)
	lag := now.Unix() - stamp
	retry := !r.nextHandoffProbe.IsZero() && r.handoffProbeSeqno == master.Block.SeqNo && !shouldSwitchNextToArchiveByLag(lag)
	if stamp == 0 || (!retry && !shouldSwitchArchiveToNextByLag(lag)) {
		return nil, nil
	}

	r.handoffProbeSeqno = master.Block.SeqNo
	r.nextHandoffProbe = now.Add(archiveCatchUpProgressInterval)
	ctx, cancel := context.WithTimeout(r.ctx, nextBlockBootstrapProbeTimeout)
	defer cancel()
	window, err := r.prepareLiveHandoff(ctx, master)
	if err != nil {
		r.archive.log.Debug().Err(err).Uint32("current", master.Block.SeqNo).Msg("live successor unavailable, continuing archive catch-up")
		return nil, r.ctx.Err()
	}
	return window, nil
}

func (r *archiveCatchUpRun) prepareLiveHandoff(ctx context.Context, master *storage.BlockState) (*shardClientArchiveWindow, error) {
	block, targets, err := r.archive.masterTransitions.probeArchiveSuccessor(ctx, master)
	if err != nil {
		return nil, err
	}
	if block.ID.SeqNo != master.Block.SeqNo+1 || block.Meta == nil || len(block.Meta.PrevRefs) != 1 || !block.Meta.PrevRefs[0].Equals(&master.Block) {
		return nil, fmt.Errorf("unexpected successor %s after %s", block.BlockRef(), storage.FormatBlockRef(master.Block))
	}
	depth, err := monitorMinSplitDepth(master, 0)
	if err != nil {
		return nil, err
	}
	blocks := make(map[storage.BlockRootHash]PreparedBlock)
	if r.archive.preparedMasterBlockAfterSyncUntil(block) {
		targets = nil
	}
	for len(targets) != 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := targets[len(targets)-1]
		targets = targets[:len(targets)-1]
		if current, ok := r.current.Shards[storage.ShardKeyFromBlock(id)]; ok && current.Block.Equals(&id) {
			continue
		}
		if existing, ok := blocks[storage.BlockKey(id)]; ok {
			if !existing.ID.Equals(&id) {
				return nil, fmt.Errorf("conflicting shard identity for %s", storage.FormatBlockRef(id))
			}
			continue
		}
		if _, err := r.archive.storage.BlockState(ctx, id); err == nil {
			continue
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		shard, err := r.archive.shardTransitions.probeArchiveShard(ctx, id)
		if err != nil {
			return nil, err
		}
		if !shard.ID.Equals(&id) || shard.Meta == nil || len(shard.Meta.PrevRefs) < 1 || len(shard.Meta.PrevRefs) > 2 {
			return nil, fmt.Errorf("invalid live shard dependency %s", storage.FormatBlockRef(id))
		}
		for _, prev := range shard.Meta.PrevRefs {
			if err := validateShardStatePrevRef(id, prev); err != nil {
				return nil, err
			}
			targets = append(targets, prev)
		}
		shard.Meta = shard.Meta.Clone()
		blocks[storage.BlockKey(id)] = shard
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	window := &shardClientArchiveWindow{
		startSeqno:     block.ID.SeqNo,
		masterSequence: []PreparedBlock{block},
		masterStates:   make(map[uint32]*storage.BlockState),
		masterProofs:   map[uint32]*masterchainConsensusProof{block.ID.SeqNo: block.consensus},
		archiveBlocks:  blocks,
		splitDepth:     depth,
		totalStats:     &archive.ImportStats{},
		stateCells:     r.archive.state.newArchiveStateCellWindow(r.stateCells.loader()),
	}
	_, err = r.applyArchiveMasterBlocks(ctx, master, window)
	if err != nil {
		return nil, err
	}
	if window.syncUntilReached {
		return window, nil
	}
	window.handoff, err = r.applyShardClientArchiveWindow(ctx, r.current, window)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return window, nil
}

func (s *SyncCoordinator) probeArchiveSuccessor(ctx context.Context, prev *storage.BlockState) (PreparedBlock, []ton.BlockIDExt, error) {
	block, _, _, err := s.downloadNextChainBlockProbe(ctx, prev.Block, blockStateUtime(ctx, s.storage, prev), &nextBlockBootstrapProbeState{liveTail: true})
	if err != nil {
		return PreparedBlock{}, nil, err
	}
	block.consensusChecked, err = s.checkedConsensusForPreparedBlock(prev, block)
	if err != nil {
		return PreparedBlock{}, nil, err
	}
	targets, _, err := shardTargetsForMasterBlock(block)
	return block, targets, err
}

func (s *SyncCoordinator) probeArchiveShard(ctx context.Context, id ton.BlockIDExt) (PreparedBlock, error) {
	block, err := s.preparedShardBlocks.take(id)
	if errors.Is(err, storage.ErrNotFound) {
		block, err = loadStoredBlockForApply(ctx, s.storage, id)
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return block, err
	}
	raw, _, err := s.downloadExactChainBlockProbe(ctx, id, exactBlockDownloadProbeState{started: time.Now()})
	if err != nil {
		return PreparedBlock{}, err
	}
	return s.prepareDownloadedBlockForApply(raw)
}
