package merkletree

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/txaty/go-merkletree/mock"
)

func NewMerkleTree() (*MerkleTree, error) {
	blocks := generatedTestDataBlocks(20)
	config := &Config{
		DisableLeafHashing: true,
		Mode:               ModeTreeBuild,
	}
	m, err := New(config, blocks)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func TestStoreToFile(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Errorf("test TestStoreToFile error %v", err)
	}

	lc, err := NewLevelCache(m, 1, 2)
	if err != nil {
		t.Errorf("test TestStoreToFile error %v", err)
	}
	if err = lc.StoreToFile("store.gob"); err != nil {
		t.Errorf("test TestStoreToFile error %v", err)
	}
	t.Log(lc)
}

func TestLevelCacheFromFileNew(t *testing.T) {
	lc, err := NewLevelCacheFromFile("store.gob")
	if err != nil {
		t.Errorf("test TestLevelCacheFromFileNew error %v", err)
	}
	assert.Equal(t, lc.Start, 1)
	assert.Equal(t, lc.Level, 2)
	t.Log(lc)
}

func TestProve(t *testing.T) {
	lc, err := NewLevelCacheFromFile("store.gob")
	if err != nil {
		t.Errorf("test TestLevelCacheFromFileNew error %v", err)
	}

	config := &Config{
		DisableLeafHashing: true,
		Mode:               ModeTreeBuild,
	}
	proof, root, err := lc.Prove(lc.Nodes[0][0], config)
	if err != nil {
		t.Errorf("test TestProve error %v", err)
	}
	t.Log(proof)
	t.Log(root)
}

func TestAppendProof(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Errorf("test TestAppendProof error %v", err)
	}

	block := &mock.DataBlock{
		Data: m.nodes[0][5],
	}
	proof, err := m.Proof(block)
	if err != nil {
		t.Errorf("test TestAppendProof error %v", err)
	}

	lc, err := NewLevelCache(m, 0, 2)
	if err != nil {
		t.Errorf("test TestAppendProof error %v", err)
	}
	lc1, err := NewLevelCache(m, 2, 3)
	if err != nil {
		t.Errorf("test TestAppendProof error %v", err)
	}

	config := &Config{
		DisableLeafHashing: true,
		Mode:               ModeTreeBuild,
	}
	p1, root, err := lc.Prove(lc.Nodes[0][5], config)
	if err != nil {
		t.Errorf("test TestAppendProof error %v", err)
	}
	p2, root1, err := lc1.Prove(root, config)
	if err != nil {
		t.Errorf("test TestAppendProof error %v", err)
	}

	proof1, err := AppendProof(p1, *p2)
	if err != nil {
		t.Errorf("test TestAppendProof error %v", err)
	}

	assert.Equal(t, proof, proof1)
	assert.Equal(t, m.Root, root1)
}
