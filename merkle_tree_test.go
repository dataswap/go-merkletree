package merkletree

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"runtime"
	"testing"

	mt "github.com/cbergoon/merkletree"
)

const benchSize = 100000

type mockDataBlock struct {
	data []byte
}

func (t *mockDataBlock) Serialize() ([]byte, error) {
	return t.data, nil
}

func genTestDataBlocks(num int) []DataBlock {
	var blocks []DataBlock
	for i := 0; i < num; i++ {
		block := &mockDataBlock{
			data: make([]byte, 100),
		}
		_, err := rand.Read(block.data)
		if err != nil {
			panic(err)
		}
		blocks = append(blocks, block)
	}
	return blocks
}

func TestMerkleTreeNew(t *testing.T) {
	type args struct {
		blocks []DataBlock
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test_0",
			args: args{
				blocks: genTestDataBlocks(0),
			},
			wantErr: false,
		},
		{
			name: "test_4",
			args: args{
				blocks: genTestDataBlocks(4),
			},
			wantErr: false,
		},
		{
			name: "test_8",
			args: args{
				blocks: genTestDataBlocks(8),
				config: &Config{
					HashFunc:        defaultHashFunc,
					AllowDuplicates: true,
				},
			},
			wantErr: false,
		},
		{
			name: "test_5",
			args: args{
				blocks: genTestDataBlocks(5),
				config: &Config{
					HashFunc:        defaultHashFunc,
					AllowDuplicates: true,
				},
			},
			wantErr: false,
		},
		{
			name: "test_1000",
			args: args{
				blocks: genTestDataBlocks(1000),
			},
			wantErr: false,
		},
		{
			name: "test_100_parallel",
			args: args{
				blocks: genTestDataBlocks(100),
				config: &Config{
					HashFunc:        defaultHashFunc,
					AllowDuplicates: true,
					RunInParallel:   true,
					NumRoutines:     4,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.args.config, tt.args.blocks); (err != nil) != tt.wantErr {
				t.Errorf("Build() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func verifySetup(size int) (*MerkleTree, []DataBlock, error) {
	blocks := genTestDataBlocks(size)
	m, err := New(&Config{
		HashFunc:        defaultHashFunc,
		AllowDuplicates: true,
	}, blocks)
	if err != nil {
		return nil, nil, err
	}
	return m, blocks, nil
}

func verifySetupParallel(size int) (*MerkleTree, []DataBlock, error) {
	blocks := genTestDataBlocks(size)
	m, err := New(&Config{
		HashFunc:        defaultHashFunc,
		AllowDuplicates: true,
		RunInParallel:   true,
		NumRoutines:     4,
	}, blocks)
	if err != nil {
		return nil, nil, err
	}
	return m, blocks, nil
}

func TestMerkleTree_Verify(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(int) (*MerkleTree, []DataBlock, error)
		blockSize int
		want      bool
		wantErr   bool
	}{
		{
			name:      "test_2",
			setupFunc: verifySetup,
			blockSize: 2,
			want:      true,
			wantErr:   false,
		},
		{
			name:      "test_3",
			setupFunc: verifySetup,
			blockSize: 3,
			want:      true,
			wantErr:   false,
		},
		{
			name:      "test_pseudo_random_4",
			setupFunc: verifySetup,
			blockSize: 4,
			want:      true,
			wantErr:   false,
		},
		{
			name:      "test_pseudo_random_5",
			setupFunc: verifySetup,
			blockSize: 5,
			want:      true,
			wantErr:   false,
		},
		{
			name:      "test_pseudo_random_6",
			setupFunc: verifySetup,
			blockSize: 6,
			want:      true,
			wantErr:   false,
		},
		{
			name:      "test_pseudo_random_8",
			setupFunc: verifySetup,
			blockSize: 8,
			want:      true,
			wantErr:   false,
		},
		{
			name:      "test_pseudo_random_9",
			setupFunc: verifySetup,
			blockSize: 9,
			want:      true,
			wantErr:   false,
		},
		{
			name:      "test_pseudo_random_10",
			setupFunc: verifySetup,
			blockSize: 10,
			want:      true,
			wantErr:   false,
		},
		{
			name:      "test_pseudo_random_1001",
			setupFunc: verifySetup,
			blockSize: 1001,
			want:      true,
			wantErr:   false,
		},
		{
			name:      "test_pseudo_random_1001_parallel",
			setupFunc: verifySetupParallel,
			blockSize: 1001,
			want:      true,
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, blocks, err := tt.setupFunc(tt.blockSize)
			if err != nil {
				t.Errorf("setupFunc() error = %v", err)
				return
			}
			for i := 0; i < tt.blockSize; i++ {
				got, err := m.Verify(blocks[i], m.Proofs[i])
				if (err != nil) != tt.wantErr {
					t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if got != tt.want {
					t.Errorf("Verify() got = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVerify(t *testing.T) {
	m, blocks, _ := verifySetup(2)
	// hashFunc is nil
	got, err := Verify(blocks[0], m.Proofs[0], []byte{}, nil)
	if err != nil {
		t.Errorf("Verify() error = %v, wantErr %v", err, nil)
		return
	}
	if got {
		t.Errorf("Verify() got = %v, want %v", got, false)
	}
}

func BenchmarkMerkleTreeProofGen(b *testing.B) {
	config := &Config{
		HashFunc:        defaultHashFunc,
		AllowDuplicates: true,
	}
	testCases := genTestDataBlocks(benchSize)
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeProofGenParallel(b *testing.B) {
	config := &Config{
		HashFunc:        defaultHashFunc,
		AllowDuplicates: true,
		RunInParallel:   true,
		NumRoutines:     runtime.NumCPU(),
	}
	testCases := genTestDataBlocks(benchSize)
	for i := 0; i < b.N; i++ {
		_, err := New(config, testCases)
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func (m mockDataBlock) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(m.data); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (m mockDataBlock) Equals(other mt.Content) (bool, error) {
	return bytes.Equal(m.data, other.(mockDataBlock).data), nil
}

func generateCberTestCases(size int) []mt.Content {
	var contents []mt.Content
	for i := 0; i < size; i++ {
		contents = append(contents, mockDataBlock{
			data: make([]byte, 100),
		})
		_, err := rand.Read(contents[i].(mockDataBlock).data)
		if err != nil {
			panic(err)
		}
	}
	return contents
}

func Benchmark_cbergoonMerkleTreeProofGen(b *testing.B) {
	contents := generateCberTestCases(benchSize)
	for i := 0; i < b.N; i++ {
		tree, err := mt.NewTree(contents)
		for j := 0; j < benchSize; j++ {
			_, _, err := tree.GetMerklePath(contents[j])
			if err != nil {
				b.Errorf("GetMerklePath() error = %v", err)
			}
		}
		if err != nil {
			b.Errorf("Build() error = %v", err)
		}
	}
}

func BenchmarkMerkleTreeVerify(b *testing.B) {
	tree, blocks, err := verifySetup(benchSize)
	if err != nil {
		b.Errorf("setupFunc() error = %v", err)
		return
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for idx := 0; idx < benchSize; idx++ {
			_, err := tree.Verify(blocks[10], tree.Proofs[10])
			if err != nil {
				b.Errorf("Verify() error = %v", err)
				return
			}
		}
	}
}

func Benchmark_cbergoonMerkleTreeVerify(b *testing.B) {
	contents := generateCberTestCases(benchSize)
	tree, err := mt.NewTree(contents)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for idx := 0; idx < benchSize; idx++ {
			_, err := tree.VerifyContent(contents[idx])
			if err != nil {
				b.Errorf("Verify() error = %v", err)
			}
		}
	}
}
