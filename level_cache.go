package merkletree

import (
	"encoding/gob"
	"os"
	"sync"
)

type LevelCache struct {
	// leafMap maps the data (converted to string) of each leaf node to its index in the Tree slice.
	LeafMap map[string]int
	// leafMapMu is a mutex that protects concurrent access to the leafMap.
	leafMapMu sync.Mutex
	// Nodes contains the Merkle Tree's internal node structure.
	Nodes [][][]byte
	// Start is the level of the cache Merkle Tree. leaf level is 0.
	Start int
	// Level is the Levels of the cache Merkle Tree.
	Level int
}

// start range:[0, depth-1]
// level range:[1, depth]
func NewLevelCache(m *MerkleTree, start int, level int) (*LevelCache, error) {

	if m == nil {
		return nil, ErrMerkleTreeIsNil
	}
	if m.Depth <= start || start < 0 {
		return nil, ErrLevelCacheStart
	}
	if m.Depth < level || level < 1 {
		return nil, ErrLevelCacheLevel
	}

	lc := LevelCache{Start: start, Level: level}

	finishMap := make(chan struct{})
	lc.LeafMap = make(map[string]int)
	go func() {
		lc.leafMapMu.Lock()
		defer lc.leafMapMu.Unlock()
		for i := 0; i < m.NumLeaves>>start; i++ {
			lc.LeafMap[string(m.nodes[start][i])] = i
		}
		finishMap <- struct{}{} // empty channel to serve as a wait group for map generation
	}()

	lc.Nodes = make([][][]byte, level)

	for i := 0; i < level; i++ {
		lc.Nodes[i] = append(lc.Nodes[i], m.nodes[start+i]...)
	}

	<-finishMap
	return &lc, nil
}

func NewLevelCacheFromFile(filePath string) (*LevelCache, error) {
	readFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer readFile.Close()
	decoder := gob.NewDecoder(readFile)

	loaded := LevelCache{}
	if err = decoder.Decode(&loaded); err != nil {
		return nil, err
	}

	return &loaded, nil
}

// Append sub tree Proof to base tree Proof
func AppendProof(base *Proof, sub Proof) (*Proof, error) {
	base.Path += sub.Path
	base.Siblings = append(base.Siblings, sub.Siblings...)
	return base, nil
}

func (lc *LevelCache) StoreToFile(filePath string) error {

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	if err = encoder.Encode(lc); err != nil {
		return err
	}
	return nil
}

func (lc *LevelCache) Prove(dataBlock DataBlock, config *Config) (*Proof, []byte, error) {

	leaf, err := dataBlockToLeaf(dataBlock, config)
	if err != nil {
		return nil, nil, err
	}

	// Retrieve the index of the leaf in the Merkle Tree.
	lc.leafMapMu.Lock()
	idx, ok := lc.LeafMap[string(leaf)]
	lc.leafMapMu.Unlock()
	if !ok {
		return nil, nil, ErrProofInvalidDataBlock
	}

	// Compute the path and siblings for the proof.
	var (
		path     uint32
		siblings = make([][]byte, lc.Level)
	)
	for i := 0; i < lc.Level; i++ {
		if idx&1 == 1 {
			siblings[i] = lc.Nodes[i][idx-1]
		} else {
			// Absolute path
			path += 1 << (i + lc.Start)
			siblings[i] = lc.Nodes[i][idx+1]
		}
		idx >>= 1
	}

	if config == nil {
		config = new(Config)
	}
	if config.HashFunc == nil {
		config.HashFunc = DefaultHashFunc
	}

	// Determine the concatenation function based on the configuration.
	concatFunc := concatHash
	if config.SortSiblingPairs {
		concatFunc = concatSortHash
	}
	// Traverse the Merkle proof and compute the root hash.
	// Copy the slice so that the original leaf won't be modified.
	root := make([]byte, len(leaf))
	copy(root, leaf)
	relativePath := path >> lc.Start
	for _, sib := range siblings {
		if relativePath&1 == 1 {
			root, err = config.HashFunc(concatFunc(root, sib))
		} else {
			root, err = config.HashFunc(concatFunc(sib, root))
		}
		if err != nil {
			return nil, nil, err
		}
		relativePath >>= 1
	}

	return &Proof{
		Path:     path,
		Siblings: siblings,
	}, root, nil
}
