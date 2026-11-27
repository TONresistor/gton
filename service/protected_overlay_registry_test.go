package service

import (
	"bytes"
	"crypto/ed25519"
	"math/big"
	"net"
	"testing"

	"github.com/xssnick/gton/internal/shardstate"
	"github.com/xssnick/gton/service/p2p"
	"github.com/xssnick/gton/service/storage"
	"github.com/xssnick/tonutils-go/address"
	adnladdr "github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

func TestProtectedRegistryReadsAccountAlongsideParsedHeader(t *testing.T) {
	id := p2p.PeerID{7}
	nodes := cell.NewDict(256)
	node, err := tlb.ToCell(protectedRegistryNode{Roles: protectedOverlayRole})
	if err != nil {
		t.Fatal(err)
	}
	if err = nodes.Set(cell.BeginCell().MustStoreSlice(id[:], 256).EndCell(), node); err != nil {
		t.Fatal(err)
	}
	empty := cell.BeginCell().EndCell()
	data, err := tlb.ToCell(protectedRegistryStorage{Nodes: nodes, Extra: empty})
	if err != nil {
		t.Fatal(err)
	}
	registryID := [32]byte{46}
	account, err := (tlb.AccountState{
		IsValid: true,
		Address: address.NewAddress(0, 255, registryID[:]),
		StorageInfo: tlb.StorageInfo{
			StorageUsed:  tlb.StorageUsed{CellsUsed: big.NewInt(1), BitsUsed: big.NewInt(1)},
			StorageExtra: tlb.StorageExtraNone{},
		},
		AccountStorage: tlb.AccountStorage{
			Status:    tlb.AccountStatusActive,
			StateInit: &tlb.StateInit{Code: empty, Data: data},
		},
	}).ToCell()
	if err != nil {
		t.Fatal(err)
	}
	shardAccount, err := tlb.ToCell(tlb.ShardAccount{Account: account, LastTransHash: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := shardstate.NewAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.Set(cell.BeginCell().MustStoreSlice(registryID[:], 256).EndCell(), shardAccount); err != nil {
		t.Fatal(err)
	}
	state := &storage.BlockState{
		Cell:   cell.BeginCell().MustStoreRef(empty).MustStoreRef(accounts.MustToCell()).EndCell(),
		Parsed: &tlb.ShardStateUnsplit{},
	}
	param := cell.BeginCell().MustStoreUInt(0x3601163f, 32).MustStoreSlice(registryID[:], 256).EndCell()
	config := cell.NewDict(32)
	if err = config.SetIntKey(big.NewInt(46), cell.BeginCell().MustStoreRef(param).EndCell()); err != nil {
		t.Fatal(err)
	}
	var cache protectedRegistryCache
	registry, err := cache.load(&tlb.BlockchainConfig{Root: config.AsCell()}, state)
	if err != nil || registry == nil || len(registry.Authorized) != 1 || registry.Authorized[0] != id {
		t.Fatalf("registry from live state = %+v, error = %v", registry, err)
	}
}

func TestProtectedRegistryProjectsRolesAndBoundAddresses(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	key := keys.PublicKeyED25519{Key: private.Public().(ed25519.PublicKey)}
	idBytes, err := tl.Hash(key)
	if err != nil {
		t.Fatal(err)
	}
	id := p2p.PeerID(idBytes)
	other := p2p.PeerID{1}
	wire, err := tl.Serialize(ProtectedRegistryADNLNode{
		ID: key,
		Address: &adnladdr.List{
			ReinitDate: 17,
			Addresses: []adnladdr.Address{
				adnladdr.UDP{IP: net.IPv4(127, 0, 0, 1), Port: 2020},
				adnladdr.QUIC{IP: net.IPv4(127, 0, 0, 1), Port: 3020},
			},
		},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := cell.BeginCell().MustStoreSlice(wire, uint(len(wire)*8)).EndCell()
	nodes := cell.NewDict(256)
	for _, peer := range []p2p.PeerID{id, other} {
		value, err := tlb.ToCell(protectedRegistryNode{Roles: protectedOverlayRole, ADNL: descriptor})
		if err != nil {
			t.Fatal(err)
		}
		if err = nodes.Set(cell.BeginCell().MustStoreSlice(peer[:], 256).EndCell(), value); err != nil {
			t.Fatal(err)
		}
	}
	var cache protectedRegistryCache
	registry, err := cache.project(nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Authorized) != 2 || len(registry.Addresses) != 1 {
		t.Fatalf("got %d roles and %d valid descriptors", len(registry.Authorized), len(registry.Addresses))
	}
	address := registry.Addresses[id]
	if !bytes.Equal(address.Key, key.Key) || address.List.ReinitDate != 0 || len(address.List.Addresses) != 2 {
		t.Fatalf("invalid registered addresses: %+v", address)
	}
	if next, err := cache.project(nodes); err != nil || next != registry {
		t.Fatalf("unchanged registry snapshot was rebuilt: %v", err)
	}
}
