package service

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/xssnick/gton/internal/shardstate"
	"github.com/xssnick/gton/service/p2p"
	"github.com/xssnick/gton/service/storage"
	adnladdr "github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const protectedOverlayRole = 2

type protectedRegistryStorage struct {
	_                      tlb.Magic        `tlb:"#9bc722a9"`
	Nodes                  *cell.Dictionary `tlb:"dict 256"`
	Votings                *cell.Dictionary `tlb:"dict 320"`
	VotingsGC              *cell.Dictionary `tlb:"dict 352"`
	Extra                  *cell.Cell       `tlb:"^"`
	LastValidatorSetUpdate uint32           `tlb:"## 32"`
}

type protectedRegistryNode struct {
	_                     tlb.Magic  `tlb:"#ac83c7be"`
	Roles                 uint32     `tlb:"## 32"`
	IsValidator           uint32     `tlb:"## 32"`
	AllowUpdateADNLNodeAt uint32     `tlb:"## 32"`
	ADNL                  *cell.Cell `tlb:"maybe ^"`
}

// ProtectedRegistryADNLNode is the adnl.node stored by the v2026.11 contract.
type ProtectedRegistryADNLNode struct {
	ID      any            `tl:"struct boxed [pub.ed25519]"`
	Address *adnladdr.List `tl:"struct"`
}

func init() {
	tl.Register(ProtectedRegistryADNLNode{}, "adnl.node id:PublicKey addr_list:adnl.addressList = adnl.Node")
}

type protectedRegistryCache struct {
	nodesHash cell.Hash
	registry  *p2p.ProtectedOverlayRegistry
}

func (c *protectedRegistryCache) load(cfg *tlb.BlockchainConfig, state *storage.BlockState) (*p2p.ProtectedOverlayRegistry, error) {
	parameter, err := cfg.GetParam(46)
	if errors.Is(err, tlb.ErrBlockchainConfigParamAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	loader, err := parameter.BeginParse()
	if err != nil {
		return nil, err
	}
	constructor, err := loader.LoadUInt(32)
	if err != nil {
		return nil, err
	}
	switch constructor {
	case 0x3601163e: // Legacy registry has no protected-overlay roles.
		return nil, nil
	case 0x3601163f:
	default:
		return nil, fmt.Errorf("unknown validator registry config constructor %08x", constructor)
	}
	address, err := loader.LoadSlice(256)
	if err != nil {
		return nil, err
	}

	// Live applied states may retain only the parsed header.
	stateLoader, err := state.Cell.BeginParse()
	if err != nil {
		return nil, err
	}
	accountsCell, err := stateLoader.PeekRefCellAt(1)
	if err != nil {
		return nil, err
	}
	accounts, err := shardstate.LoadAccountsRoot(accountsCell)
	if err != nil {
		return nil, err
	}
	var accountLoader cell.Slice
	if err = accounts.LoadValueByBytesKeyInto(address, &accountLoader); errors.Is(err, cell.ErrNoSuchKeyInDict) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var shardAccount tlb.ShardAccount
	if err = tlb.LoadFromCell(&shardAccount, &accountLoader); err != nil {
		return nil, err
	}
	data, err := shardAccount.Account.BeginParse()
	if err != nil {
		return nil, err
	}
	var account tlb.AccountState
	if err = tlb.LoadFromCell(&account, data); err != nil {
		return nil, err
	}
	if !account.IsValid || account.Status != tlb.AccountStatusActive || account.StateInit == nil ||
		account.StateInit.Code == nil || account.StateInit.Data == nil {
		return nil, nil
	}
	// The v2026.11 reader recognizes the former contract by its code hash.
	if fmt.Sprintf("%x", account.StateInit.Code.HashKey()) == "10b3b24d2f21600f24e6dabb9df6368a544893752170f4c4e34ecfd267d24cac" {
		return nil, nil
	}
	stateData, err := account.StateInit.Data.BeginParse()
	if err != nil {
		return nil, err
	}
	var registry protectedRegistryStorage
	if err = tlb.LoadFromCell(&registry, stateData); err != nil {
		return nil, err
	}
	return c.project(registry.Nodes)
}

func (c *protectedRegistryCache) project(nodes *cell.Dictionary) (*p2p.ProtectedOverlayRegistry, error) {
	if nodes == nil || nodes.AsCell() == nil {
		return nil, nil
	}
	hash := nodes.AsCell().HashKey()
	if hash == c.nodesHash && c.registry != nil {
		return c.registry, nil
	}

	entries, err := nodes.LoadAll()
	if err != nil {
		return nil, err
	}
	registry := &p2p.ProtectedOverlayRegistry{Addresses: make(map[p2p.PeerID]p2p.ProtectedOverlayAddress)}
	for _, entry := range entries {
		var node protectedRegistryNode
		if err = tlb.LoadFromCell(&node, entry.Value); err != nil {
			continue // The reference skips an invalid node entry.
		}
		key, err := entry.Key.LoadSlice(256)
		if err != nil {
			return nil, err
		}
		id := p2p.PeerID(key)
		if node.Roles&protectedOverlayRole != 0 {
			registry.Authorized = append(registry.Authorized, id)
		}
		if address, ok := protectedRegistryAddress(id, node.ADNL); ok {
			registry.Addresses[id] = address
		}
	}
	c.nodesHash, c.registry = hash, registry
	return registry, nil
}

func protectedRegistryAddress(id p2p.PeerID, descriptor *cell.Cell) (p2p.ProtectedOverlayAddress, bool) {
	if descriptor == nil {
		return p2p.ProtectedOverlayAddress{}, false
	}
	s, err := descriptor.BeginParse()
	if err != nil || s.RefsNum() != 0 || s.BitsLeft()%8 != 0 {
		return p2p.ProtectedOverlayAddress{}, false
	}
	wire, err := s.LoadSlice(s.BitsLeft())
	if err != nil {
		return p2p.ProtectedOverlayAddress{}, false
	}
	var node ProtectedRegistryADNLNode
	rest, err := tl.Parse(&node, wire, true)
	if err != nil || len(rest) != 0 || node.Address == nil {
		return p2p.ProtectedOverlayAddress{}, false
	}
	key, ok := node.ID.(keys.PublicKeyED25519)
	if !ok {
		return p2p.ProtectedOverlayAddress{}, false
	}
	hash, err := tl.Hash(key)
	if err != nil || !bytes.Equal(id[:], hash) {
		return p2p.ProtectedOverlayAddress{}, false
	}
	node.Address.ReinitDate = 0
	return p2p.ProtectedOverlayAddress{Key: key.Key, List: node.Address}, true
}
